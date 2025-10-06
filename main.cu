#include <cstdio>
#include <cstdlib>

// generate password by extracting each of the idx then convert it to base-36
__device__ void generatePassword(unsigned long long idx,
                                 char *password, int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    const int charset_size = 36;

    for (int i = length - 1; i >= 0; i--) {
        password[i] = charset[idx % charset_size];
        idx /= charset_size;
    }
    password[length] = '\0';
}

__global__ void passwordGenKernel(char *password, int password_length,
                                  unsigned long long start_idx) {
    int idx = blockDim.x * blockIdx.x + threadIdx.x;

    unsigned long long password_idx = start_idx + idx;

    // this counts the place where we store the generated password to memory
    char *password_point = password + (idx * (password_length + 1));
    generatePassword(password_idx, password_point, password_length);
}

int main() {
    const int PASSWORD_NUM = 1024;
    const int PASSWORD_LENGTH = 4;
    // because at the end of every string in memory is this character '\0'
    const int PASSWORD_SIZE= PASSWORD_LENGTH + 1;

    char *d_passwords, *h_passwords;

    // allocate memory
    h_passwords = (char*)malloc(PASSWORD_NUM * PASSWORD_SIZE);
    cudaMalloc(&d_passwords, PASSWORD_NUM * PASSWORD_SIZE);

    passwordGenKernel<<<16, 16>>>(d_passwords, PASSWORD_LENGTH, 0);

    cudaMemcpy(h_passwords, d_passwords, PASSWORD_NUM * PASSWORD_SIZE,
               cudaMemcpyDeviceToHost);

    for(int i = 0; i < 20; i++) {
        printf("Password %d: %s\n", i, h_passwords + (i * PASSWORD_SIZE));
    }

    free(h_passwords);
    cudaFree(d_passwords);

    return 0;
}
