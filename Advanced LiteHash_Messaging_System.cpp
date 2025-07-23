// ==============================================================================
// PROJECT: Advanced Secure Lightweight Messaging System using LiteHash (C++ Version)
// ==============================================================================


#include <iostream>
#include <vector>
#include <string>
#include <cstdint> // For fixed-width integers like uint64_t
#include <map>     
#include <set>     // Equivalent to Python's set
#include <random>  // For generating random numbers and distributions
#include <utility> // For std::pair
#include <stdexcept> // For std::invalid_argument and std::runtime_error
#include <cmath>   // For std::round

// Use the standard namespace to avoid prefixing std:: everywhere
using namespace std;

// ==============================================================================
// PART 1: CORE LITEHASH APPROXIMATION FUNCTIONS
// ==============================================================================

namespace LiteHash {

    /**
     * @brief Ensures the result is a 64-bit unsigned integer.
     */
    uint64_t mask64(uint64_t n) {
        return n & 0xFFFFFFFFFFFFFFFF;
    }

    /**
     * @brief Simulates the Approximate Summer Unit (ASU) using a bitwise XOR.
     */
    uint64_t _approximate_summer_unit(uint64_t a_3bit, uint64_t b_3bit) {
        return a_3bit ^ b_3bit;
    }

    /**
     * @brief Simulates the LiteHash#3 approximate addition algorithm.
     */
    uint64_t approximate_add_v3(uint64_t a, uint64_t b) {
        uint64_t result = 0;
        // Handle the least significant bit with a simple XOR
        result |= ((a & 1) ^ (b & 1));

        // Process the remaining 63 bits in 3-bit chunks using the ASU
        for (int i = 0; i < 21; ++i) {
            int shift = (i * 3) + 1;
            uint64_t mask = 0b111ULL << shift; // ULL for unsigned long long literal
            uint64_t a_chunk = (a & mask) >> shift;
            uint64_t b_chunk = (b & mask) >> shift;
            uint64_t sum_chunk = _approximate_summer_unit(a_chunk, b_chunk);
            result |= (sum_chunk << shift);
        }

        return mask64(result);
    }

} // namespace LiteHash

// ==============================================================================
// PART 2: ADVANCED SECURE MESSAGING SYSTEM
// ==============================================================================

class SecureMessagingSystem {
private:
    uint64_t _salt;
    map<string, uint64_t> _registered_users; // Stores ideal_key for each user_id
    map<string, uint64_t> _active_sessions;  // Stores session_key for logged-in users
    map<string, set<uint64_t>> _used_nonces; // Stores used nonces for each user

    /**
     * @brief Derives a 64-bit key from a biometric vector using LiteHash#3.
     */
    uint64_t _derive_key_from_biometrics(const vector<uint8_t>& biometric_vector) {
        if (biometric_vector.size() != 3) {
            throw invalid_argument("Input vector must have 3 elements.");
        }

        uint64_t packed_input = (static_cast<uint64_t>(biometric_vector[0]) << 16) |
                                (static_cast<uint64_t>(biometric_vector[1]) << 8)  |
                                 static_cast<uint64_t>(biometric_vector[2]);

        return LiteHash::approximate_add_v3(packed_input, this->_salt);
    }

public:
    /**
     * @brief Constructor to initialize the system with a salt.
     */
    SecureMessagingSystem(uint64_t salt = 0xDEADBEEFCAFEF00D) : _salt(salt) {}

    /**
     * @brief Step 1: Registers a user with their ideal biometric signature.
     */
    void register_user(const string& user_id, const vector<uint8_t>& ideal_biometric_vector) {
        uint64_t ideal_key = _derive_key_from_biometrics(ideal_biometric_vector);
        _registered_users[user_id] = ideal_key;
        _used_nonces[user_id] = set<uint64_t>(); // Initialize the set of used nonces
        cout << "[System] User '" << user_id << "' registered successfully." << endl;
    }

    /**
     * @brief Step 2: Logs a user in by comparing current biometrics to the registered key.
     */
    bool login(const string& user_id, const vector<uint8_t>& current_biometric_vector) {
        if (_registered_users.find(user_id) == _registered_users.end()) {
            cout << "[Login FAILED] User '" << user_id << "' is not registered." << endl;
            return false;
        }

        uint64_t registered_key = _registered_users[user_id];
        uint64_t current_key = _derive_key_from_biometrics(current_biometric_vector);

        if (current_key == registered_key) {
            _active_sessions[user_id] = current_key;
            cout << "[Login SUCCESS] Session established for user '" << user_id << "'." << endl;
            return true;
        } else {
            cout << "[Login FAILED] Biometric mismatch for user '" << user_id << "'." << endl;
            return false;
        }
    }

    /**
     * @brief Step 3: Creates a secure digest (MAC) for a message.
     * @return A pair containing the digest and the nonce.
     */
    pair<uint64_t, uint64_t> create_secure_digest(const string& user_id, const string& message) {
        if (_active_sessions.find(user_id) == _active_sessions.end()) {
            throw runtime_error("User '" + user_id + "' is not logged in.");
        }

        uint64_t session_key = _active_sessions[user_id];

        // Generate a random 64-bit nonce
        random_device rd;
        mt19937_64 gen(rd());
        uniform_int_distribution<uint64_t> dis;
        uint64_t nonce = dis(gen);

        uint64_t packed_message = 0;
        for (size_t i = 0; i < message.length(); ++i) {
            packed_message += static_cast<uint64_t>(static_cast<uint8_t>(message[i])) << ((i % 8) * 8);
        }

        // This simulates H(key || message || nonce)
        uint64_t temp_hash = LiteHash::approximate_add_v3(session_key, packed_message);
        uint64_t digest = LiteHash::approximate_add_v3(temp_hash, nonce);

        return {digest, nonce};
    }

    /**
     * @brief Step 4: Verifies a message and checks for replay attacks.
     */
    bool verify_message(const string& user_id, const string& message, uint64_t received_digest, uint64_t nonce) {
        if (_active_sessions.find(user_id) == _active_sessions.end()) {
            throw runtime_error("User '" + user_id + "' is not logged in.");
        }

        // SECURITY CHECK: Prevent replay attacks
        if (_used_nonces[user_id].count(nonce)) {
            cout << "  [Verification FAILED] Replay attack detected! Nonce " << hex << nonce << dec << " has already been used." << endl;
            return false;
        }

        // Re-calculate the digest
        uint64_t session_key = _active_sessions[user_id];
        uint64_t packed_message = 0;
        for (size_t i = 0; i < message.length(); ++i) {
            packed_message += static_cast<uint64_t>(static_cast<uint8_t>(message[i])) << ((i % 8) * 8);
        }
        uint64_t temp_hash = LiteHash::approximate_add_v3(session_key, packed_message);
        uint64_t recalculated_digest = LiteHash::approximate_add_v3(temp_hash, nonce);

        // Check if digests match
        if (recalculated_digest == received_digest) {
            _used_nonces[user_id].insert(nonce); // Record nonce as used
            return true;
        } else {
            return false;
        }
    }
};

// ==============================================================================
// PART 3: SYSTEM DEMONSTRATION
// ==============================================================================

int main() {
    // --- System Setup ---
    SecureMessagingSystem system;
    cout << string(70, '=') << endl;
    cout << " ADVANCED SECURE LIGHTWEIGHT MESSAGING SYSTEM: DEMONSTRATION (C++)" << endl;
    cout << string(70, '=') << endl;

    // --- Step 1: User Registration ---
    cout << "\n--- [WORKFLOW STEP 1: REGISTRATION] ---" << endl;
    system.register_user("Vikram", {208, 127, 85});
    system.register_user("Alice", {10, 20, 30});

    // --- Step 2: Successful Login for Both Users ---
    cout << "\n--- [WORKFLOW STEP 2: USER LOGIN] ---" << endl;
    
    // Setup for generating biometric noise
    random_device rd;
    mt19937 gen(rd());
    normal_distribution<> d(0, 2.0);

    // Vikram's login attempt with noise
    vector<uint8_t> vikram_ideal = {208, 127, 85};
    vector<uint8_t> vikram_biometrics;
    cout << "'Vikram' attempts to log in with biometric data: [";
    for(uint8_t val : vikram_ideal) {
        uint8_t noisy_val = static_cast<uint8_t>(val + static_cast<int>(round(d(gen))));
        vikram_biometrics.push_back(noisy_val);
        cout << " " << static_cast<int>(noisy_val);
    }
    cout << " ]" << endl;
    bool vikram_login = system.login("Vikram", vikram_biometrics);

    // Alice's login attempt with noise
    vector<uint8_t> alice_ideal = {10, 20, 30};
    vector<uint8_t> alice_biometrics;
    cout << "'Alice' attempts to log in with biometric data: [";
    for(uint8_t val : alice_ideal) {
        uint8_t noisy_val = static_cast<uint8_t>(val + static_cast<int>(round(d(gen))));
        alice_biometrics.push_back(noisy_val);
        cout << " " << static_cast<int>(noisy_val);
    }
    cout << " ]" << endl;
    bool alice_login = system.login("Alice", alice_biometrics);


    // --- Step 3 & 4: Secure Messaging and Verification ---
    if (vikram_login) {
        cout << "\n--- [WORKFLOW STEP 3 & 4: SECURE MESSAGING] ---" << endl;
        string message_to_send = "This is a secret message from Vikram.";
        cout << "[Sender: Vikram] Creating secure digest for message: '" << message_to_send << "'" << endl;
        
        auto [digest, nonce] = system.create_secure_digest("Vikram", message_to_send);
        cout << "  -> Secure Digest (MAC): " << hex << digest << dec << endl;
        cout << "  -> Nonce: " << hex << nonce << dec << endl;

        cout << "\n[Receiver: Vikram] Verifying received message..." << endl;
        bool is_valid = system.verify_message("Vikram", message_to_send, digest, nonce);
        cout << "  -> Verification Result: " << (is_valid ? "true" : "false") << endl;
        if (is_valid) {
            cout << "  \xE2\x9C\x85 SUCCESS: The message is authentic and has not been tampered with." << endl;
        } else {
            cout << "  \xE2\x9D\x8C FAILURE: Verification failed." << endl;
        }

        // --- Step 5: Replay Attack Demonstration ---
        cout << "\n--- [WORKFLOW STEP 5: REPLAY ATTACK ATTEMPT] ---" << endl;
        cout << "[Attacker] Intercepts the message and tries to replay it..." << endl;
        cout << "[Receiver: Vikram] Verifying the SAME message and nonce again..." << endl;
        bool is_valid_replay = system.verify_message("Vikram", message_to_send, digest, nonce);
        cout << "  -> Verification Result: " << (is_valid_replay ? "true" : "false") << endl;
        if (!is_valid_replay) {
            cout << "  \xE2\x9C\x85 SUCCESS: The system correctly identified and blocked the replay attack." << endl;
        } else {
            cout << "  \xE2\x9D\x8C FAILURE: The system failed to block the replay attack." << endl;
        }
    }

    // --- Step 6: Failed Login Attempt (Imposter) ---
    cout << "\n--- [WORKFLOW STEP 6: IMPOSTER LOGIN ATTEMPT] ---" << endl;
    string imposter_id = "Imposter";
    vector<uint8_t> imposter_biometrics = {100, 50, 25};
    cout << "'" << imposter_id << "' attempts to log in with biometric data: [ 100 50 25 ]" << endl;
    system.login(imposter_id, imposter_biometrics);
    cout << "  \xE2\x9C\x85 SUCCESS: The system correctly prevented the imposter from logging in." << endl;

    cout << "\n" << string(70, '=') << endl;

    return 0;
}
