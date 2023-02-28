// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.10;

library DateTime {
    uint256 constant DAY_IN_SECONDS = 86400;
    uint256 constant YEAR_IN_SECONDS = 31536000;
    uint256 constant LEAP_YEAR_IN_SECONDS = 31622400;

    uint256 constant HOUR_IN_SECONDS = 3600;
    uint256 constant MINUTE_IN_SECONDS = 60;

    uint16 constant ORIGIN_YEAR = 1970;

    function isLeapYear(uint16 year) private pure returns (bool) {
        if (year % 4 != 0) {
            return false;
        }
        if (year % 100 != 0) {
            return true;
        }
        if (year % 400 != 0) {
            return false;
        }
        return true;
    }

    function toTimestamp(
        uint16 year,
        uint8 month,
        uint8 day,
        uint8 hour,
        uint8 minute,
        uint8 second
    ) private pure returns (uint256 timestamp) {
        uint16 i;

        // Year
        for (i = ORIGIN_YEAR; i < year; i++) {
            if (isLeapYear(i)) {
                timestamp += LEAP_YEAR_IN_SECONDS;
            } else {
                timestamp += YEAR_IN_SECONDS;
            }
        }

        // Month
        uint8[12] memory monthDayCounts;
        monthDayCounts[0] = 31;
        if (isLeapYear(year)) {
            monthDayCounts[1] = 29;
        } else {
            monthDayCounts[1] = 28;
        }
        monthDayCounts[2] = 31;
        monthDayCounts[3] = 30;
        monthDayCounts[4] = 31;
        monthDayCounts[5] = 30;
        monthDayCounts[6] = 31;
        monthDayCounts[7] = 31;
        monthDayCounts[8] = 30;
        monthDayCounts[9] = 31;
        monthDayCounts[10] = 30;
        monthDayCounts[11] = 31;

        for (i = 1; i < month; i++) {
            timestamp += DAY_IN_SECONDS * monthDayCounts[i - 1];
        }

        // Day
        timestamp += DAY_IN_SECONDS * (day - 1);

        // Hour
        timestamp += HOUR_IN_SECONDS * (hour);

        // Minute
        timestamp += MINUTE_IN_SECONDS * (minute);

        // Second
        timestamp += second;

        return timestamp;
    }

    function toTimestamp(bytes memory x509Time) public pure returns (uint256) {
        uint16 yrs;
        uint8 mnths;
        uint8 dys;
        uint8 hrs;
        uint8 mins;
        uint8 secs;
        uint8 offset;

        if (x509Time.length == 13) {
            if (uint8(x509Time[0]) - 48 < 5) yrs += 2000;
            else yrs += 1900;
        } else {
            yrs +=
                (uint8(x509Time[0]) - 48) *
                1000 +
                (uint8(x509Time[1]) - 48) *
                100;
            offset = 2;
        }
        yrs +=
            (uint8(x509Time[offset + 0]) - 48) *
            10 +
            uint8(x509Time[offset + 1]) -
            48;
        mnths =
            (uint8(x509Time[offset + 2]) - 48) *
            10 +
            uint8(x509Time[offset + 3]) -
            48;
        dys +=
            (uint8(x509Time[offset + 4]) - 48) *
            10 +
            uint8(x509Time[offset + 5]) -
            48;
        hrs +=
            (uint8(x509Time[offset + 6]) - 48) *
            10 +
            uint8(x509Time[offset + 7]) -
            48;
        mins +=
            (uint8(x509Time[offset + 8]) - 48) *
            10 +
            uint8(x509Time[offset + 9]) -
            48;
        secs +=
            (uint8(x509Time[offset + 10]) - 48) *
            10 +
            uint8(x509Time[offset + 11]) -
            48;

        return toTimestamp(yrs, mnths, dys, hrs, mins, secs);
    }
}
