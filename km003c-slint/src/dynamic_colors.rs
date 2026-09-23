//! The system's dynamic Material colours, on Android 14 and later.
//!
//! `java/.../DynamicColors.java` reads every colour role of the wallpaper-derived
//! scheme and hands them over as one `variant.role=AARRGGBB` string. The roles
//! it provides replace those of the Material library's default palette; the
//! rest keep their defaults. The library then picks the light or dark scheme
//! from the system theme itself.

use std::collections::HashMap;

use slint::Color;

use crate::MaterialScheme;

/// Overwrite the roles of `scheme` that `listing` gives for `variant`
/// (`light` or `dark`). Returns how many roles were set.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn apply_roles(scheme: &mut MaterialScheme, listing: &str, variant: &str) -> usize {
    let roles: HashMap<&str, Color> = listing
        .lines()
        .filter_map(|line| {
            let (key, hex) = line.split_once('=')?;
            let (line_variant, role) = key.split_once('.')?;
            let argb = u32::from_str_radix(hex, 16).ok()?;
            (line_variant == variant).then_some((role, Color::from_argb_encoded(argb)))
        })
        .collect();

    let mut applied = 0;
    macro_rules! set_roles {
        ($($field:ident),* $(,)?) => {
            $(
                if let Some(color) = roles.get(stringify!($field)) {
                    scheme.$field = *color;
                    applied += 1;
                }
            )*
        };
    }
    set_roles!(
        primary,
        surfaceTint,
        onPrimary,
        primaryContainer,
        onPrimaryContainer,
        secondary,
        onSecondary,
        secondaryContainer,
        onSecondaryContainer,
        tertiary,
        onTertiary,
        tertiaryContainer,
        onTertiaryContainer,
        error,
        onError,
        errorContainer,
        onErrorContainer,
        background,
        onBackground,
        surface,
        onSurface,
        surfaceVariant,
        onSurfaceVariant,
        outline,
        outlineVariant,
        surfaceDim,
        surfaceBright,
        surfaceContainerLowest,
        surfaceContainerLow,
        surfaceContainer,
        surfaceContainerHigh,
        surfaceContainerHighest,
        primaryFixed,
        primaryFixedDim,
        onPrimaryFixed,
        onPrimaryFixedVariant,
        secondaryFixed,
        secondaryFixedDim,
        onSecondaryFixed,
        onSecondaryFixedVariant,
        tertiaryFixed,
        tertiaryFixedDim,
        onTertiaryFixed,
        onTertiaryFixedVariant,
    );
    applied
}

#[cfg(target_os = "android")]
pub use android::apply;

#[cfg(target_os = "android")]
mod android {
    use jni::objects::{JObject, LoaderContext};
    use jni::{JavaVM, bind_java_type};
    use slint::ComponentHandle;
    use slint::android::AndroidApp;
    use tracing::{info, warn};

    use super::apply_roles;
    use crate::{App, MaterialPalette};

    bind_java_type! {
        Context => android.content.Context,
        methods {
            fn get_class_loader {
                name = "getClassLoader",
                sig = () -> JClassLoader,
            },
        },
    }

    bind_java_type! {
        DynamicColors => "dev.okhsunrog.km003c.DynamicColors",
        type_map = {
            Context => "android.content.Context",
        },
        constructors {
            fn new(context: Context),
        },
        methods {
            fn scheme {
                name = "scheme",
                sig = () -> JString,
            },
        },
    }

    /// Install the system's dynamic colours, keeping the default palette when
    /// they are unavailable.
    pub fn apply(ui: &App, app: &AndroidApp) {
        let listing = match read(app) {
            Ok(listing) => listing,
            Err(error) => {
                warn!("Could not read the system's dynamic colours: {error}");
                return;
            }
        };
        if listing.is_empty() {
            info!("Dynamic colours need Android 14; keeping the default palette");
            return;
        }

        let palette = ui.global::<MaterialPalette>();
        let mut schemes = palette.get_schemes();
        let applied =
            apply_roles(&mut schemes.light, &listing, "light") + apply_roles(&mut schemes.dark, &listing, "dark");
        palette.set_schemes(schemes);
        info!("Applied {applied} dynamic colour roles");
    }

    fn read(app: &AndroidApp) -> Result<String, jni::errors::Error> {
        // Slint has usually created the JavaVM singleton by now; adopt the
        // process VM if it has not.
        if JavaVM::singleton().is_err() {
            // SAFETY: android-activity documents vm_as_ptr() as the process
            // JavaVM, which is what JavaVM::from_raw expects.
            unsafe { JavaVM::from_raw(app.vm_as_ptr() as *mut _) };
        }

        JavaVM::singleton()?.attach_current_thread(|env| {
            // SAFETY: activity_as_ptr() is the Activity jobject, alive for as
            // long as the activity is.
            let activity = unsafe { JObject::from_raw(env, app.activity_as_ptr() as *mut _) };
            let context = Context::cast_local(env, activity)?;

            // A thread attached from native code finds classes through the
            // system class loader, which does not know the app's own classes.
            let loader = context.get_class_loader(env)?;
            DynamicColorsAPI::get(env, &LoaderContext::Loader(&loader))?;

            let colors = DynamicColors::new(env, &context)?;
            let listing = colors.scheme(env)?;
            listing.try_to_string(env)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_of_the_requested_variant_replace_the_defaults() {
        let mut scheme = MaterialScheme::default();
        let listing = "light.primary=ff112233\ndark.primary=ff445566\nlight.onSurface=80aabbcc\n";

        let applied = apply_roles(&mut scheme, listing, "light");

        assert_eq!(applied, 2);
        assert_eq!(scheme.primary, Color::from_argb_u8(0xff, 0x11, 0x22, 0x33));
        assert_eq!(scheme.onSurface, Color::from_argb_u8(0x80, 0xaa, 0xbb, 0xcc));
    }

    #[test]
    fn unknown_roles_and_malformed_lines_are_ignored() {
        let mut scheme = MaterialScheme::default();
        let listing = "light.notARole=ff000000\nlight.primary=nothex\ngarbage\n";

        assert_eq!(apply_roles(&mut scheme, listing, "light"), 0);
        assert_eq!(scheme, MaterialScheme::default());
    }
}
