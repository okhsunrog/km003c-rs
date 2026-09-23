package dev.okhsunrog.km003c;

import android.content.Context;
import android.os.Build;

/**
 * The Material 3 colour roles of the system's dynamic theme.
 *
 * <p>Android 14 exposes every role of the wallpaper-derived scheme as a colour
 * resource, in a light and a dark variant. The names here are the SDK's own
 * symbols, so {@code javac} checks them; transcribed into Rust they would be
 * strings nothing checks until they run.
 *
 * <p>The whole scheme crosses to Rust as one string, {@code variant.role=AARRGGBB}
 * per line, which costs one JNI call instead of one per colour. Role names are
 * those of Slint's {@code MaterialScheme}. Roles the system does not provide
 * (the inverse roles, shadow, scrim) are left out and keep the library's
 * defaults.
 */
public final class DynamicColors {

    private final Context context;
    private final StringBuilder out = new StringBuilder(4096);

    public DynamicColors(Context context) {
        this.context = context;
    }

    /** The scheme, or an empty string before Android 14. */
    public String scheme() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            return "";
        }
        out.setLength(0);

        role("primary", android.R.color.system_primary_light, android.R.color.system_primary_dark);
        // Material defines surface tint as the primary colour.
        role("surfaceTint", android.R.color.system_primary_light, android.R.color.system_primary_dark);
        role("onPrimary", android.R.color.system_on_primary_light, android.R.color.system_on_primary_dark);
        role("primaryContainer", android.R.color.system_primary_container_light,
                android.R.color.system_primary_container_dark);
        role("onPrimaryContainer", android.R.color.system_on_primary_container_light,
                android.R.color.system_on_primary_container_dark);

        role("secondary", android.R.color.system_secondary_light, android.R.color.system_secondary_dark);
        role("onSecondary", android.R.color.system_on_secondary_light, android.R.color.system_on_secondary_dark);
        role("secondaryContainer", android.R.color.system_secondary_container_light,
                android.R.color.system_secondary_container_dark);
        role("onSecondaryContainer", android.R.color.system_on_secondary_container_light,
                android.R.color.system_on_secondary_container_dark);

        role("tertiary", android.R.color.system_tertiary_light, android.R.color.system_tertiary_dark);
        role("onTertiary", android.R.color.system_on_tertiary_light, android.R.color.system_on_tertiary_dark);
        role("tertiaryContainer", android.R.color.system_tertiary_container_light,
                android.R.color.system_tertiary_container_dark);
        role("onTertiaryContainer", android.R.color.system_on_tertiary_container_light,
                android.R.color.system_on_tertiary_container_dark);

        role("error", android.R.color.system_error_light, android.R.color.system_error_dark);
        role("onError", android.R.color.system_on_error_light, android.R.color.system_on_error_dark);
        role("errorContainer", android.R.color.system_error_container_light,
                android.R.color.system_error_container_dark);
        role("onErrorContainer", android.R.color.system_on_error_container_light,
                android.R.color.system_on_error_container_dark);

        role("background", android.R.color.system_background_light, android.R.color.system_background_dark);
        role("onBackground", android.R.color.system_on_background_light, android.R.color.system_on_background_dark);
        role("surface", android.R.color.system_surface_light, android.R.color.system_surface_dark);
        role("onSurface", android.R.color.system_on_surface_light, android.R.color.system_on_surface_dark);
        role("surfaceVariant", android.R.color.system_surface_variant_light,
                android.R.color.system_surface_variant_dark);
        role("onSurfaceVariant", android.R.color.system_on_surface_variant_light,
                android.R.color.system_on_surface_variant_dark);
        role("outline", android.R.color.system_outline_light, android.R.color.system_outline_dark);
        role("outlineVariant", android.R.color.system_outline_variant_light,
                android.R.color.system_outline_variant_dark);

        role("surfaceDim", android.R.color.system_surface_dim_light, android.R.color.system_surface_dim_dark);
        role("surfaceBright", android.R.color.system_surface_bright_light,
                android.R.color.system_surface_bright_dark);
        role("surfaceContainerLowest", android.R.color.system_surface_container_lowest_light,
                android.R.color.system_surface_container_lowest_dark);
        role("surfaceContainerLow", android.R.color.system_surface_container_low_light,
                android.R.color.system_surface_container_low_dark);
        role("surfaceContainer", android.R.color.system_surface_container_light,
                android.R.color.system_surface_container_dark);
        role("surfaceContainerHigh", android.R.color.system_surface_container_high_light,
                android.R.color.system_surface_container_high_dark);
        role("surfaceContainerHighest", android.R.color.system_surface_container_highest_light,
                android.R.color.system_surface_container_highest_dark);

        // Fixed roles are the same in both variants.
        fixed("primaryFixed", android.R.color.system_primary_fixed);
        fixed("primaryFixedDim", android.R.color.system_primary_fixed_dim);
        fixed("onPrimaryFixed", android.R.color.system_on_primary_fixed);
        fixed("onPrimaryFixedVariant", android.R.color.system_on_primary_fixed_variant);
        fixed("secondaryFixed", android.R.color.system_secondary_fixed);
        fixed("secondaryFixedDim", android.R.color.system_secondary_fixed_dim);
        fixed("onSecondaryFixed", android.R.color.system_on_secondary_fixed);
        fixed("onSecondaryFixedVariant", android.R.color.system_on_secondary_fixed_variant);
        fixed("tertiaryFixed", android.R.color.system_tertiary_fixed);
        fixed("tertiaryFixedDim", android.R.color.system_tertiary_fixed_dim);
        fixed("onTertiaryFixed", android.R.color.system_on_tertiary_fixed);
        fixed("onTertiaryFixedVariant", android.R.color.system_on_tertiary_fixed_variant);

        return out.toString();
    }

    private void role(String name, int light, int dark) {
        entry("light", name, light);
        entry("dark", name, dark);
    }

    private void fixed(String name, int id) {
        role(name, id, id);
    }

    private void entry(String variant, String name, int id) {
        out.append(variant).append('.').append(name).append('=')
                .append(Integer.toHexString(context.getColor(id))).append('\n');
    }
}
