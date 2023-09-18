#include "headers.h"
#include "KeyStruct.h"
#include "error.h"
#define PORT 8080
using namespace std;


void Decrypt(int new_socket,unsigned char* digest, string uname,unsigned char** clear_buf_out, size_t* clear_size_out, size_t* aad1_out, size_t* aad2_out, size_t* aad3_out)
{
	int ret; // used for return values
	const EVP_CIPHER* cipher = EVP_aes_128_gcm();
   int iv_len = EVP_CIPHER_iv_length(cipher);
    // Assume key is hard-coded (this is not a good thing, but it is not our focus right now)
   int key_len = EVP_CIPHER_key_length(cipher);

   unsigned char *key = (unsigned char*)malloc(key_len);;//(unsigned char *)"0123456789012345";

   memcpy(key, digest, key_len);

 

    //Receive add and its size
	size_t aad_len;
	read(new_socket, &aad_len, sizeof(size_t));

	unsigned char* aad = (unsigned char*)malloc(aad_len);
	read(new_socket, aad, aad_len);

    size_t tag_len;
	read(new_socket, &tag_len, sizeof(size_t));

     size_t cphr_size;
	read(new_socket, &cphr_size, sizeof(size_t));
    
	//Receive Client Buffer and its size
	size_t final_size;
	read(new_socket, &final_size, sizeof(size_t));

	unsigned char* final_buf = (unsigned char*)malloc(final_size);

    //  int chunk_size = 1024; // Adjust this to match the client's chunk size

    read(new_socket, final_buf, final_size);
//   cout<<"aad_len: "<<aad_len<<"\n tag_len: "<<tag_len<<endl;
// cout<<"\n Inside decrypt !!!"<<endl;
unsigned char* iv = (unsigned char*)malloc(EVP_CIPHER_iv_length(cipher));
unsigned char* cphr_buf = (unsigned char*)malloc(cphr_size);
unsigned char* tag_buf = (unsigned char*)malloc(tag_len);

// Extract iv
memcpy(iv, final_buf, EVP_CIPHER_iv_length(cipher));

// Extract cphr_buf
memcpy(cphr_buf, final_buf + EVP_CIPHER_iv_length(cipher), cphr_size);

// Extract tag_buf
memcpy(tag_buf, final_buf + EVP_CIPHER_iv_length(cipher) + cphr_size, tag_len);
// cout<<"content of iv"<<endl;

//  BIO_dump_fp (stdout, (const char *)iv, iv_len);


   unsigned char* clear_buf = (unsigned char*)malloc(cphr_size);
   if(!clear_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
   cout<<"/n this is cphr size"<<cphr_size<<endl;


   //Create and initialise the context
      EVP_CIPHER_CTX *ctx;
    int len=0;
    int plaintext_len=0;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("EVP_CIPHER_CTX_new failed");
    if(!EVP_DecryptInit(ctx, cipher, key, iv))
        handleErrors("EVP_DecryptInit failed");
	//Provide any AAD data.
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors("EVP_DecryptUpdate failed");
	//Provide the message to be decrypted, and obtain the plaintext output.
  int x=0;

       cout<<"/n after update"<<x<<endl;
    if(1 != EVP_DecryptUpdate(ctx, clear_buf + plaintext_len, &len, cphr_buf + plaintext_len, cphr_size)){
        perror("Errore: EVP_EncryptUpdate\n");
        exit(-1);
    }
    plaintext_len += len;

   
   
  cout<<"/n after update"<<plaintext_len<<endl;
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag_buf))
        handleErrors("EVP_CIPHER_CTX_ctrl");
    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal(ctx, clear_buf + len, &len);
    if(ret < 0){
        perror("Error: EVP_DecryptFinal\n");
        exit(1);
    }

    /* Clean up */
    EVP_CIPHER_CTX_cleanup(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        
    } else {
        /* Verify failed */
        //return -1;
    }

    int clear_size= plaintext_len;

           // Allocate memory for clear_buf_out
    *clear_buf_out = (unsigned char*)malloc(clear_size);

     if (clear_buf_out == NULL) {
        perror("Error allocating memory for clear_buf");
        exit(1);
    }

    // Copy the decrypted data to clear_buf_out
    memcpy(*clear_buf_out, clear_buf, clear_size);

    // Set clear_size_out
    *clear_size_out = clear_size;


   // Extract the sizes
    size_t extracted_size_aad1;
    int offset = 0;
    memcpy(&extracted_size_aad1, aad + offset, sizeof(size_t));
    offset += sizeof(size_t);
    
    size_t extracted_size_aad2;
    memcpy(&extracted_size_aad2, aad + offset, sizeof(size_t));
    offset += sizeof(extracted_size_aad2);
    size_t extracted_size_aad3;
    memcpy(&extracted_size_aad3, aad + offset, sizeof(size_t));
    

    *aad1_out = extracted_size_aad1;
    *aad2_out = extracted_size_aad2;
    *aad3_out = extracted_size_aad3;

   // delete the plaintext from memory:
   // Telling the compiler it MUST NOT optimize the following instruction. 
   // With optimization the memset would be skipped, because of the next free instruction.
#pragma optimize("", off)
   memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
   free(clear_buf);


   // deallocate buffers:
   free(iv);
   free(tag_buf);
   free(cphr_buf);
   free(aad);
   free(final_buf);
   free(key);
}

void Encrypt(int sock,unsigned char* digest, string uname,unsigned char* clear_buf_new, size_t clear_size_new,size_t aad1_new,size_t aad2_new,size_t aad3_new)
{
   int ret; // used for return values

   const EVP_CIPHER* cipher = EVP_aes_128_gcm();
   int iv_len = EVP_CIPHER_iv_length(cipher);
   size_t block_size = EVP_CIPHER_block_size(cipher);

     // Assume key is hard-coded (this is not a good thing, but it is not our focus right now)
   size_t key_len = EVP_CIPHER_key_length(cipher);

   unsigned char *key = (unsigned char*)malloc(key_len);;//(unsigned char *)"0123456789012345";

   memcpy(key, digest, key_len);

   unsigned char* clear_buf = (unsigned char*)malloc(clear_size_new);
   memcpy(clear_buf, clear_buf_new, clear_size_new);
   size_t clear_size= clear_size_new;


        // Define components of the AAD
    size_t aad1 = aad1_new;
    size_t aad2 = aad2_new;
    size_t aad3 = aad3_new;

    // Calculate the size of each component
    size_t size_aad1 = sizeof(size_t);
    size_t size_aad2 = sizeof(size_t);
    size_t size_aad3 = sizeof(size_t); // Include null terminator

    // Calculate the total size needed for iv
    size_t total_size = size_aad1 +size_aad2 + size_aad3;
    // printf("file_size: %zu\n", size_aad1);
    // printf("counter: %zu\n", size_aad2);
    // printf("operation_type: %zu\n", size_aad3);
    //  printf("total_size: %zu\n", total_size);
     
    // Allocate memory for iv
    unsigned char* aad = (unsigned char*)malloc(total_size);

    // Allocate memory for iv
    unsigned char* iv = (unsigned char*)malloc(iv_len);

    if (iv == NULL) {
        perror("Memory allocation failed");
        //return 1;
    }

    RAND_poll();
   // Generate 16 bytes at random. That is my IV
   ret = RAND_bytes((unsigned char*)&iv[0],iv_len);
   if(ret!=1){
	  cerr <<"Error: RAND_bytes Failed\n";
      exit(1);
   } 

    

    // Copy the sizes and data into the iv buffer
    size_t offset = 0;
    memcpy(aad + offset, &aad1, size_aad1);
    offset += size_aad1;
    memcpy(aad + offset, &aad2, size_aad2);
    offset += size_aad2;
    memcpy(aad + offset, &aad3, size_aad3);

    // Read and print the contents of the iv buffer
    // printf("Contents of iv: ");
    // for (size_t i = 0; i < total_size; i++) {
    //     printf("%02x ", aad[i]);
    // }
    // printf("\n");
   
   // check for possible integer overflow in (clear_size + block_size) --> PADDING!
   // (possible if the plaintext is too big, assume non-negative clear_size and block_size):
   if(clear_size > UINT_MAX - block_size) { cerr <<"Error: integer overflow (file too big?)\n"; exit(1); }
   // allocate a buffer for the ciphertext:
   size_t enc_buffer_size = clear_size + block_size;
   unsigned char* cphr_buf = (unsigned char*)malloc(enc_buffer_size);
   if(!cphr_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }

   unsigned char *tag_buf;
   size_t tag_len = 16;
   tag_buf=(unsigned char*)malloc(tag_len);
   
//     cout<<"Used IV:"<<endl;
//    BIO_dump_fp (stdout, (const char *)iv, iv_len);
   
   
   //Create and initialise the context with used cipher, key and iv
    EVP_CIPHER_CTX *ctx;
    int len=0;
    int ciphertext_len=0;
    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("EVP_CIPHER_CTX_new");
    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit(ctx, cipher, key, iv))
        handleErrors("EVP_EncryptInit");

    //Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, total_size))
        handleErrors("EncryptUpdate");

      if(1 != EVP_EncryptUpdate(ctx, cphr_buf + ciphertext_len, &len, clear_buf + ciphertext_len, clear_size)){
        perror("Errore: EVP_EncryptUpdate\n");
        exit(-1);
    }
    
    ciphertext_len += len;
    cout<<"/n after update"<<ciphertext_len<<endl;
	
    if(1 != EVP_EncryptFinal(ctx, cphr_buf + len, &len)){
        perror("Errore: EVP_EncryptFinal\n");
        exit(-1);
    }
    
    ciphertext_len += len;
    
    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag_buf))
        handleErrors("EVP_CIPHER_CTX_");
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    size_t cphr_size = ciphertext_len;
   //  return ciphertext_len;
   // With optimization the memset would be skipped, because of the next free instruction.
#pragma optimize("", off)
   memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
   free(clear_buf);


   //Send aad and size
  send(sock, &total_size, sizeof(size_t), 0);
  send(sock, aad, total_size, 0);

//   send(sock, cphr_buf, cphr_size, 0);

  send(sock, &tag_len, sizeof(size_t), 0);
//   send(sock, tag_buf, tag_len, 0);
    cout<<"\n cphr_size: "<<cphr_size<<endl;
   send(sock, &cphr_size, sizeof(size_t), 0);

size_t final_length= cphr_size+tag_len+iv_len;
unsigned char* final_cphr = (unsigned char*)malloc(final_length);

  // Copy iv
memcpy(final_cphr, iv, iv_len);

// Copy cphr_buf
memcpy(final_cphr + iv_len, cphr_buf, cphr_size);

// Copy tag_buf
memcpy(final_cphr + iv_len + cphr_size, tag_buf, tag_len);


  //Send cipher buffer and size
  send(sock, &final_length, sizeof(size_t), 0);

        send(sock, final_cphr, final_length, 0);
 
   // deallocate buffers:
   free(cphr_buf);
   free(iv);
   free(tag_buf);
   free(aad);
   free(final_cphr);
   free(key);
}