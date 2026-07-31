package ch.admin.bj.swiyu.didtoolbox.model;


import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ProfileVersionTest {

    @Test
    void toString_returnsFormattedProfileVersion() {
        assertEquals("swiss-profile-anchor:1.0.0", ProfileVersion.SWISS_PROFILE_ANCHOR_1_0_0.toString());
    }

    @Test
    void getLatest_returnsProfileAnchor1_0_0() {
        assertEquals(ProfileVersion.SWISS_PROFILE_ANCHOR_1_0_0, ProfileVersion.getLatest());
    }
}
