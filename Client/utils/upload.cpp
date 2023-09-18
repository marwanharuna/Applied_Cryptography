#include "headers.h"
#include "error.h"

#define PORT 8080
using namespace std;

void client_upload(int sock,unsigned char* digest, string uname)
{
   int ret; // used for return values

   const EVP_CIPHER* cipher = EVP_aes_128_gcm();
   size_t iv_len = EVP_CIPHER_iv_length(cipher);
   size_t block_size = EVP_CIPHER_block_size(cipher);

     // Assume key is hard-coded (this is not a good thing, but it is not our focus right now)
   size_t key_len = EVP_CIPHER_key_length(cipher);

   unsigned char *key = (unsigned char*)malloc(key_len);;//(unsigned char *)"0123456789012345";

   memcpy(key, digest, key_len);
   
//    // read the file to encrypt from keyboard:
//    string clear_file_name;
//    cout << "Please, type the file to Upload: ";
//    cin>>clear_file_name;
//    //const char* clear_file_name = clear_file_name1.c_str();
//     cout<<"\n Inside client upload"<<endl;
//    // open the file to encrypt:
// //    FILE* clear_file = fopen(clear_file_name.c_str(), "rb");
//     // open the file to encrypt:
//    FILE* clear_file = fopen(("./Client/local/"+uname+"/Upload/"+clear_file_name).c_str(), "rb");
//    if(!clear_file) { cerr << "Error: cannot open file '" << clear_file_name << "' (file does not exist?)\n"; exit(1); }

//    // get the file size: 
//    // (assuming no failures in fseek() and ftell())
//    fseek(clear_file, 0, SEEK_END);
//    size_t clear_size = ftell(clear_file);
//    fseek(clear_file, 0, SEEK_SET);

//    // read the plaintext from file:
//    unsigned char* clear_buf = (unsigned char*)malloc(clear_size);
//    if(!clear_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
//    ret = fread(clear_buf, 1, clear_size, clear_file);
//    if(ret < clear_size) { cerr << "Error while reading file '" << clear_file_name << "'\n"; exit(1); }
//    fclose(clear_file);

std::string clear_file_name;

    std::cout << "Please, type the file to Upload: ";
    std::cin >> clear_file_name;

    std::cout << "\n Inside client upload" << std::endl;
    cout<<"\n Uname: "<<uname<<endl;
    // Open the file to encrypt using std::ifstream:
    std::ifstream clear_file("./Client/local/" + uname + "/Upload/" + clear_file_name, std::ios::binary);
    
    if (!clear_file.is_open()) {
        std::cerr << "Error: cannot open file '" << clear_file_name << "' (file does not exist?)\n";
        exit(1);
    }

    // Get the file size:
    clear_file.seekg(0, std::ios::end);
    size_t clear_size = clear_file.tellg();
    clear_file.seekg(0, std::ios::beg);

    // Read the plaintext from file:
    unsigned char* clear_buf = new unsigned char[clear_size];
    if (!clear_buf) {
        std::cerr << "Error: new returned NULL (file too big?)\n";
        exit(1);
    }

    clear_file.read(reinterpret_cast<char*>(clear_buf), clear_size);

    if (!clear_file) {
        std::cerr << "Error while reading file '" << clear_file_name << "'\n";
        exit(1);
    }


   cout<<"/n size of clearsize"<<endl<<clear_size<<endl;


        // Define components of the AAD
    size_t file_size = 123456;
    size_t counter = 42;
    size_t operation_type = 10;

    // Calculate the size of each component
    size_t size_file_size = sizeof(size_t);
    size_t size_counter = sizeof(size_t);
    size_t size_operation_type = sizeof(size_t); // Include null terminator

    // Calculate the total size needed for iv
    size_t total_size = size_file_size +size_counter + size_operation_type;
    // printf("file_size: %zu\n", size_file_size);
    // printf("counter: %zu\n", size_counter);
    // printf("operation_type: %zu\n", size_operation_type);
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
    memcpy(aad + offset, &file_size, size_file_size);
    offset += size_file_size;
    memcpy(aad + offset, &counter, size_counter);
    offset += size_counter;
    memcpy(aad + offset, &operation_type, size_operation_type);

    // // Read and print the contents of the iv buffer
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
   
    cout<<"Used IV:"<<endl;
   BIO_dump_fp (stdout, (const char *)iv, iv_len);
   
   
   //Create and initialise the context with used cipher, key and iv
    EVP_CIPHER_CTX *ctx;
    int len=0;
    size_t ciphertext_len=0;
    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("EVP_CIPHER_CTX_new failed");
    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit(ctx, cipher, key, iv))
        handleErrors("EVP_EncryptInit() failed");

    //Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, total_size))
        handleErrors("EVP_EncryptUpdate");

      while((ciphertext_len<(clear_size-8)) && clear_size>8){
        if( 1!= EVP_EncryptUpdate(ctx, cphr_buf + ciphertext_len, &len, clear_buf + ciphertext_len, 8)){
            perror("Errore: EVP_EncryptUpdate\n");
            exit(-1);
        }
        ciphertext_len += len;
        clear_size -= len;
    }
    
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
        handleErrors("EVP_CIPHER_CTX_ctrl failed");
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


    //send filename and len
  size_t file_len = clear_file_name.length();
  char* file_name =  (char*) malloc(file_len+1);
  file_name[file_len] = '\0';
  strcpy(file_name, clear_file_name.c_str());
  send(sock,&file_len, sizeof(size_t), 0);
  cout<<"\n File len: "<<file_len<<endl;
  send(sock, file_name, file_len, 0);

//  cout<<"file_name_1:"<<endl;

// cout<<"/n"<<clear_file_name<<endl; 

// cout<<"file_name:"<<endl;
// BIO_dump_fp (stdout, (const char *)file_name, file_len);

//       printf("Contents of file _name: ");
//     for (size_t i = 0; i < file_len; i++) {
//         printf("%02x ", file_name[i]);
//     }
//     printf("\n");


//   send(sock, cphr_buf, cphr_size, 0);

  send(sock, &tag_len, sizeof(size_t), 0);
//   send(sock, tag_buf, tag_len, 0);

   send(sock, &cphr_size, sizeof(size_t), 0);

size_t final_length= cphr_size+tag_len+iv_len;
unsigned char* final_cphr = (unsigned char*)malloc(final_length);
cout<<"\n tag_len: "<<tag_len<<"\n cphr_size: "<<cphr_size<<"\n final_ length: "<<final_length<<endl;
  // Copy iv
memcpy(final_cphr, iv, iv_len);

// Copy cphr_buf
memcpy(final_cphr + iv_len, cphr_buf, cphr_size);

// Copy tag_buf
memcpy(final_cphr + iv_len + cphr_size, tag_buf, tag_len);


  //Send cipher buffer and size
  send(sock, &final_length, sizeof(size_t), 0);

    // Send cipher buffer and size (in chunks)
    size_t chunk_size = 1024; // Adjust this to an appropriate value
    size_t remainder = final_length % chunk_size;

    if(final_length<chunk_size)
    {
        send(sock, final_cphr, final_length, 0);
    }
    else
    {
                
        size_t bytes_sent = 0;

        while (bytes_sent < final_length) {
            size_t remaining_bytes = final_length - bytes_sent;
            size_t bytes_to_send = (remaining_bytes < chunk_size) ? remaining_bytes : chunk_size;

            size_t sent = send(sock, final_cphr + bytes_sent, bytes_to_send, 0);
            if (sent < 0) {
                perror("Error sending data");
                exit(1);
            }

            bytes_sent += sent;
}
       
    }


   

   // deallocate buffers:
   free(cphr_buf);
   free(iv);
   free(tag_buf);
   free(aad);
   free(file_name);
   free(final_cphr);
   free(key);
}
