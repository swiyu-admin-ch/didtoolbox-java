package ch.admin.bj.swiyu.didtoolbox.model;

/**
 * Enum defining all versions of the Swiss Profile Anchor.
 */
public enum ProfileVersion {
    SWISS_PROFILE_ANCHOR_1_0_0("swiss-profile-anchor:1.0.0");

    private final String value;
    ProfileVersion(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return this.value;
    }

    public static ProfileVersion getLatest() {
        return ProfileVersion.SWISS_PROFILE_ANCHOR_1_0_0;
    }
}
