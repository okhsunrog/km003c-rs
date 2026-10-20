struct PlotParams {
    write_pos:       u32,
    num_samples:     u32,   // == ring-buffer capacity
    y_min:           f32,
    y_max:           f32,
    num_channels:    u32,
    visible_samples: u32,
    texture_width:   u32,
    texture_height:  u32,
    view_offset:     u32,   // samples to shift back from write_pos (for pan)
    scale:           f32,   // physical pixels per logical pixel (hidpi)
    x_min_hi:        f32,
    x_min_lo:        f32,
    x_span:          f32,
    timed:           u32,
    _pad0:           u32,
    _pad1:           u32,
};


@group(0) @binding(4) var<uniform> params: PlotParams;
@group(0) @binding(3) var<storage, read> times: array<vec2<f32>>;

// Timestamps use a high/low pair to retain detail far from time zero.
fn sample_x(index: u32) -> f32 {
    if params.timed == 0u { return f32(index) / f32(params.visible_samples - 1u); }
    let start = (params.write_pos + params.num_samples - params.visible_samples - params.view_offset) % params.num_samples;
    let time = times[(start + index) % params.num_samples];
    return ((time.x - params.x_min_hi) + (time.y - params.x_min_lo)) / params.x_span;
}
@group(0) @binding(0) var<storage, read> samples: array<f32>;
@group(0) @binding(2) var<storage, read_write> peaks: array<vec4<f32>>;

// One invocation per physical column/channel. No truncation: every sample
// contributing to the column is included, even for very narrow plots.
@compute @workgroup_size(64)
fn reduce(@builtin(global_invocation_id) id: vec3<u32>) {
    let index = id.x;
    if index >= params.texture_width * params.num_channels { return; }
    let column = index / params.num_channels;
    let channel = index % params.num_channels;
    let center = (f32(column) + 0.5) / f32(params.texture_width) * f32(params.visible_samples - 1u);
    let half_span = max(f32(params.visible_samples) / f32(params.texture_width) * 0.5, 0.5);
    var first = u32(max(floor(center - half_span), 0.0));
    var last = u32(min(ceil(center + half_span), f32(params.visible_samples - 1u)));
    let left = f32(column) / f32(params.texture_width);
    let right = f32(column + 1u) / f32(params.texture_width);
    if params.timed != 0u {
        first = lower_bound(left);
        last = lower_bound(right);
        if first > 0u { first -= 1u; }
        last = min(last, params.visible_samples - 1u);
    }
    let start = (params.write_pos + params.num_samples - params.visible_samples - params.view_offset) % params.num_samples;
    var lo = 3.402823e38f;
    var hi = -3.402823e38f;
    var valid = 0.0;
    for (var i = first; i <= last; i++) {
        var v = samples[((start + i) % params.num_samples) * params.num_channels + channel];
        if params.timed != 0u {
            let x = sample_x(i);
            // Clip boundary segments before taking extrema, so offscreen
            // samples don't spread their full amplitude into edge columns.
            var neighbour = i;
            var boundary = x;
            if x < left && i + 1u < params.visible_samples { neighbour = i + 1u; boundary = left; }
            if x > right && i > 0u { neighbour = i - 1u; boundary = right; }
            if x < left || x > right {
                let nx = sample_x(neighbour);
                if neighbour == i || boundary < min(x, nx) || boundary > max(x, nx) { continue; }
                let nv = samples[((start + neighbour) % params.num_samples) * params.num_channels + channel];
                if (bitcast<u32>(nv) & 0x7f800000u) == 0x7f800000u { continue; }
                v = mix(v, nv, clamp((boundary - x) / (nx - x), 0.0, 1.0));
            }
        }
        if (bitcast<u32>(v) & 0x7f800000u) != 0x7f800000u {
            lo = min(lo, v);
            hi = max(hi, v);
            valid = 1.0;
        }
    }
    peaks[index] = vec4<f32>(lo, hi, valid, 0.0);
}

// Binary search in logical ring order, including irregular sampling intervals.
fn lower_bound(x: f32) -> u32 {
    var lo = 0u;
    var hi = params.visible_samples;
    while lo < hi {
        let mid = lo + (hi - lo) / 2u;
        if sample_x(mid) < x { lo = mid + 1u; } else { hi = mid; }
    }
    return lo;
}
