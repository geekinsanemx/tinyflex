#pragma once
#include <libhackrf/hackrf.h>
#include <cstdint>
#include <cstdio>

inline hackrf_device* setup_hackrf(uint64_t frequency, uint32_t sample_rate, int tx_gain) {
    hackrf_device* device = nullptr;
   
    int result = hackrf_init();
    if (result != HACKRF_SUCCESS) {
        printf("hackrf_init() failed: %s\n", hackrf_error_name((hackrf_error)result));
        return nullptr;
    }
   
    result = hackrf_open(&device);
    if (result != HACKRF_SUCCESS) {
        printf("hackrf_open() failed: %s\n", hackrf_error_name((hackrf_error)result));
        hackrf_exit();
        return nullptr;
    }
   
    result = hackrf_set_sample_rate(device, sample_rate);
    if (result != HACKRF_SUCCESS) {
        printf("hackrf_set_sample_rate() failed\n");
    }
   
    result = hackrf_set_freq(device, frequency);
    if (result != HACKRF_SUCCESS) {
        printf("hackrf_set_freq() failed\n");
    }
   
    result = hackrf_set_txvga_gain(device, tx_gain); // 0-47 dB
    if (result != HACKRF_SUCCESS) {
        printf("hackrf_set_txvga_gain() failed\n");
    }

    return device;
}

inline void close_hackrf(hackrf_device* device) {
    if (device) {
        hackrf_close(device);
    }

    hackrf_exit();
}
