#pragma once
#include <vector>
#include <cmath>

#ifndef M_TAU
#define M_TAU 6.28318530717958647692
#endif

/**
 * Generates an FSK modulated signal based on binary data.
 * This function uses a Numerically Controlled Oscillator (NCO) to generate
 * the FSK signal by varying the frequency based on the binary data.
 * Each bit is represented by a number of samples defined by samples_per_symbol.
 * The output is a vector of doubles representing the FSK modulated signal,
 * interleaved as [I0, Q0, I1, Q1, ...].
 *
 * @param binary_data           A vector of integers (0s and 1s) representing the binary data to be modulated.
 * @param freq_0                The frequency for binary '0'.
 * @param freq_1                The frequency for binary '1'.
 * @param sample_rate           The sample rate at which the signal is generated (samples per second).
 * @param samples_per_symbol    The number of samples per symbol,
 *                              which determines the duration of each bit in the output signal.
 *
 * @return std::vector<double>  A vector of doubles representing the FSK modulated I/Q signal interleaved as [I, Q, ...].
 */
inline std::vector<double> generate_fsk_signal(
        const std::vector<int>& binary_data,
        double                  freq_0,
        double                  freq_1,
        double                  sample_rate,
        int                     samples_per_symbol
) {
    std::vector<double> output_signal;
    output_signal.reserve(binary_data.size() * samples_per_symbol * 2);

    double phase = 0.0;
    double freq_step_0 = M_TAU * freq_0 / sample_rate;
    double freq_step_1 = M_TAU * freq_1 / sample_rate;

    for (int bit : binary_data) {
        double freq_step = (bit == 0) ? freq_step_0 : freq_step_1;
        for (int i = 0; i < samples_per_symbol; ++i) {
            double I = std::cos(phase);
            double Q = std::sin(phase);
            output_signal.push_back(I);
            output_signal.push_back(Q);
            phase += freq_step;
            if (phase > M_TAU) phase -= M_TAU;
            if (phase < 0) phase += M_TAU;
        }
    }
    return output_signal;
}
