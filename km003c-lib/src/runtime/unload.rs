//! Scoped browser navigation protection, shared by independent operations.

/// Ask the browser to warn before leaving while an operation holds this guard.
///
/// Each guard owns one reference: completing one operation cannot remove the
/// warning needed by another. Browsers may still allow navigation, and require
/// prior user interaction before showing a prompt. On native platforms this
/// guard has no effect.
#[must_use = "keep the guard alive until the operation finishes"]
pub struct UnloadGuard {
    #[cfg(target_arch = "wasm32")]
    _local: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl UnloadGuard {
    pub fn new() -> Self {
        #[cfg(target_arch = "wasm32")]
        browser::retain();
        Self {
            #[cfg(target_arch = "wasm32")]
            _local: std::marker::PhantomData,
        }
    }
}

impl Default for UnloadGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for UnloadGuard {
    fn drop(&mut self) {
        #[cfg(target_arch = "wasm32")]
        browser::release();
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen(inline_js = "
let operations = 0;
const warnBeforeUnload = event => { event.preventDefault(); event.returnValue = ''; };
export function retainUnloadGuard() {
    if (operations++ === 0) window.addEventListener('beforeunload', warnBeforeUnload);
}
export function releaseUnloadGuard() {
    if (--operations === 0) window.removeEventListener('beforeunload', warnBeforeUnload);
}
")]
    extern "C" {
        #[wasm_bindgen(js_name = retainUnloadGuard)]
        pub fn retain();
        #[wasm_bindgen(js_name = releaseUnloadGuard)]
        pub fn release();
    }
}
