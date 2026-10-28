// Run against "trunk serve": NODE_PATH=<playwright node_modules> node this-file
// No hardware emulation: checks rendering, permission cancellation and open timeout.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

(async () => {
    const browser = await chromium.launch({
        executablePath: process.env.CHROMIUM || '/usr/bin/chromium',
        headless: true,
        args: ['--no-sandbox', '--enable-unsafe-swiftshader', '--enable-unsafe-webgpu', '--use-angle=swiftshader'],
    });
    try {
        const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
        const errors = [];
        page.on('pageerror', error => errors.push(String(error)));
        await page.addInitScript(() => {
            window.usbRequests = [];
            // nusb returns None for a rejected permission request.
            navigator.usb.requestDevice = async options => {
                window.usbRequests.push({ options, active: navigator.userActivation.isActive });
                if (window.hangOpen) {
                    return {
                        vendorId: 0x5fc9, productId: 0x0063,
                        serialNumber: 'test-only', configurations: [],
                        open: () => new Promise(() => {}),
                    };
                }
                throw new DOMException('Test cancellation', 'NotFoundError');
            };
        });
        // Compile the actual shared kernels in a browser on a device with no
        // optional features. Native pixel tests cover waveform correctness.
        const shaderDir = path.resolve(__dirname, '../../realtime-plot/src');
        const shaderPage = await browser.newPage();
        const shaderUrl = new URL('/kernel-test', process.env.KM003C_URL || 'http://127.0.0.1:8080').href;
        await shaderPage.route(shaderUrl, route => route.fulfill({ contentType: 'text/html', body: 'WebGPU kernel test' }));
        await shaderPage.goto(shaderUrl);
        await shaderPage.evaluate(async ({ line, reduce }) => {
            // Retain these references through asynchronous SwiftShader compilation.
            window.kernelAdapter = await navigator.gpu.requestAdapter();
            const device = window.kernelDevice = await window.kernelAdapter.requestDevice();
            const shader = device.createShaderModule({ code: line });
            const compute = device.createShaderModule({ code: reduce });
            await device.createComputePipelineAsync({
                layout: 'auto', compute: { module: compute, entryPoint: 'reduce' },
            });
            for (const [vertex, fragment] of [['vs_line', 'fs_line'], ['vs_main', 'fs_main']]) {
                await device.createRenderPipelineAsync({
                    layout: 'auto', vertex: { module: shader, entryPoint: vertex },
                    fragment: { module: shader, entryPoint: fragment, targets: [{ format: 'rgba8unorm' }] },
                });
            }
            device.destroy();
            delete window.kernelDevice;
            delete window.kernelAdapter;
        }, {
            line: fs.readFileSync(path.join(shaderDir, 'shader.wgsl'), 'utf8'),
            reduce: fs.readFileSync(path.join(shaderDir, 'reduce.wgsl'), 'utf8'),
        });
        await shaderPage.close();
        await page.goto(process.env.KM003C_URL || 'http://127.0.0.1:8080');
        await page.waitForFunction(() => !document.getElementById('notice'), { timeout: 60000 });
        assert.equal(await page.evaluate(() => Boolean(navigator.gpu)), true, 'WebGPU is required');
        const connect = () => page.mouse.click(35, 60);
        await connect();
        await page.waitForFunction(() => window.usbRequests.length === 1);
        assert.equal(await page.evaluate(() => window.usbRequests[0].active), true);
        const filters = await page.evaluate(() => window.usbRequests[0].options.filters);
        assert.deepEqual(filters, [{ vendorId: 0x5fc9, productId: 0x0063 }]);
        // Cancelled dialog must leave Connect available, without automatic prompts.
        await page.waitForTimeout(500);
        await page.evaluate(() => { window.hangOpen = true; });
        await connect();
        await page.waitForFunction(() => window.usbRequests.length === 2);
        // Opening a non-responsive device must time out, allowing another attempt.
        await page.waitForTimeout(11000);
        await page.evaluate(() => { window.hangOpen = false; });
        await connect();
        await page.waitForFunction(() => window.usbRequests.length === 3);
        assert.deepEqual(errors, []);
        console.log('PASS: WebGPU egui rendering, user activation, VID/PID filter, cancellation, open timeout, retry');
    } finally {
        await browser.close();
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
