#include <iostream>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
#include <cassert>
#include <print>

#include <oqs/oqs.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

constexpr int PORT = 5555;
constexpr int MAX_MSG_SIZE = 1024;
const char* KEM_NAME = "Kyber512";

// AES-GCM parameters
constexpr int AES_KEY_LEN = 32;
constexpr int AES_IV_LEN = 12;
constexpr int AES_TAG_LEN = 16;

// Send all bytes
bool send_all(int sock, const uint8_t* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t r = send(sock, buf + sent, len - sent, 0);
        if (r <= 0) return false;
        sent += r;
    }
    return true;
}

// Receive exact length
bool recv_all(int sock, uint8_t* buf, size_t len) {
    size_t received = 0;
    while (received < len) {
        ssize_t r = recv(sock, buf + received, len - received, 0);
        if (r <= 0) return false;
        received += r;
    }
    return true;
}

// AES-GCM encrypt
bool aes_encrypt(const uint8_t* plaintext, size_t plaintext_len,
                 const uint8_t* key, uint8_t* ciphertext,
                 uint8_t* iv, uint8_t* tag) {
    RAND_bytes(iv, AES_IV_LEN);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv))
        return false;

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return false;

    int ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return false;

    ciphertext_len += len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_LEN, tag))
        return false;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// AES-GCM decrypt
bool aes_decrypt(const uint8_t* ciphertext, size_t ciphertext_len,
                 const uint8_t* key, const uint8_t* iv, const uint8_t* tag,
                 uint8_t* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv))
        return false;

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return false;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_LEN, (void*)tag))
        return false;

    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    return ret > 0;
}

void server() {
    std::println("[server] Starting...");

    OQS_KEM* kem = OQS_KEM_new(KEM_NAME);
    assert(kem);

    std::vector<uint8_t> pk(kem->length_public_key);
    std::vector<uint8_t> sk(kem->length_secret_key);
    std::vector<uint8_t> ct(kem->length_ciphertext);
    std::vector<uint8_t> ss_server(kem->length_shared_secret);

    assert(OQS_KEM_keypair(kem, pk.data(), sk.data()) == OQS_SUCCESS);

    // Socket setup
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::println(stderr, "Port already in use. Exiting.");
        close(sockfd);
        return;
    }
    listen(sockfd, 1);

    std::println("[server] Waiting for connection...");
    int client = accept(sockfd, nullptr, nullptr);
    std::println("[server] Client connected.");

    // Send public key
    send_all(client, pk.data(), pk.size());

    // Receive ciphertext
    recv_all(client, ct.data(), ct.size());

    // Decapsulate
    OQS_KEM_decaps(kem, ss_server.data(), ct.data(), sk.data());

    for (size_t i = 0; i < kem->length_shared_secret; ++i)
        std::print("{:02x}", ss_server[i]);
    std::println();


    std::println("[server] Shared secret established.");

    // Receive encrypted message
    uint8_t iv[AES_IV_LEN], tag[AES_TAG_LEN];
    uint8_t ciphertext[MAX_MSG_SIZE];
    uint8_t plaintext[MAX_MSG_SIZE];

    uint32_t msg_len;
    recv_all(client, reinterpret_cast<uint8_t*>(&msg_len), sizeof(msg_len));

    recv_all(client, iv, AES_IV_LEN);
    recv_all(client, tag, AES_TAG_LEN);
    recv_all(client, ciphertext, msg_len);

    if (aes_decrypt(ciphertext, msg_len, ss_server.data(), iv, tag, plaintext)) {
        std::string_view message(reinterpret_cast<const char*>(plaintext), msg_len);
        std::println("[server] Received (decrypted): {}", message);
    } else {
        std::println("[server] Decryption failed.");
    }

    OQS_KEM_free(kem);
    close(client);
    close(sockfd);
}

void client() {
    std::println("[client] Starting...");

    OQS_KEM* kem = OQS_KEM_new(KEM_NAME);
    assert(kem);

    std::vector<uint8_t> pk(kem->length_public_key);
    std::vector<uint8_t> ct(kem->length_ciphertext);
    std::vector<uint8_t> ss_client(kem->length_shared_secret);

    // Socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    while (connect(sockfd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        std::println(stderr, "[client] Waiting for server...");
        std::this_thread::sleep_for(std::chrono::seconds(1));
    };
    std::println("[client] Connected to server.");

    // Receive public key
    recv_all(sockfd, pk.data(), pk.size());

    // Encapsulate
    OQS_KEM_encaps(kem, ct.data(), ss_client.data(), pk.data());

    // Send ciphertext
    send_all(sockfd, ct.data(), ct.size());
    std::println("[client] Shared secret established.");

    for (size_t i = 0; i < kem->length_shared_secret; ++i)
        std::print("{:02x}", ss_client[i]);
    std::println();

    std::string msg = "Started from the bottom now we're here!";
    uint8_t iv[AES_IV_LEN], tag[AES_TAG_LEN];
    std::vector<uint8_t> ciphertext(msg.size());

    aes_encrypt((uint8_t*)msg.data(), msg.size(), ss_client.data(), ciphertext.data(), iv, tag);

    // Send length of ciphertext first
    uint32_t msg_len = msg.size();
    send_all(sockfd, reinterpret_cast<uint8_t*>(&msg_len), sizeof(msg_len));

    // Then send IV, tag, and ciphertext
    send_all(sockfd, iv, AES_IV_LEN);
    send_all(sockfd, tag, AES_TAG_LEN);
    send_all(sockfd, ciphertext.data(), msg_len);


    OQS_KEM_free(kem);
    close(sockfd);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::println(stderr, "Usage: ./pqchat [server|client]");
        return 1;
    }

    std::string mode = argv[1];
    if (mode == "server") {
        server();
    } else if (mode == "client") {
        client();
    } else {
        std::println(stderr, "Invalid mode: {}", mode);
        return 1;
    }

    return 0;
}
