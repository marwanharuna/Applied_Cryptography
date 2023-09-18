#include "headers.h"
#include "error.h"
#define PORT 8080
using namespace std;


void cloud_upload(int new_socket,unsigned char* digest, string uname)
{
	int ret; // used for return values
	const EVP_CIPHER* cipher = EVP_aes_128_gcm();
   size_t iv_len = EVP_CIPHER_iv_length(cipher);

   // Assume key is hard-coded (this is not a good thing, but it is not our focus right now)
   size_t key_len = EVP_CIPHER_key_length(cipher);

   unsigned char *key = (unsigned char*)malloc(key_len);;//(unsigned char *)"0123456789012345";

   memcpy(key, digest, key_len);
   // read the file to decrypt from keyboard:
//    string cphr_file_name;
   //cout << "Please, type the file to decrypt: ";
   	//Receive IV
	// Allocate memory for and randomly generate IV:
   	// unsigned char* iv = (unsigned char*)malloc(iv_len);
	// read(new_socket, iv, iv_len);

    //Receive add and its size
	size_t aad_len;
	read(new_socket, &aad_len, sizeof(size_t));

	unsigned char* aad = (unsigned char*)malloc(aad_len);
	read(new_socket, aad, aad_len);

    
	//Receive file size and name
	size_t file_len1;
	read(new_socket,&file_len1, sizeof(size_t));
	char* file_name1 =  (char*) malloc(file_len1+1);
    file_name1[file_len1] = '\0';
	read(new_socket, file_name1, file_len1);
   
	string cphr_file_name;
	cphr_file_name.assign(file_name1, file_len1);
    cout<<"file_name:"<<endl;
//    BIO_dump_fp (stdout, (const char *)file_name1, file_len1);

    size_t tag_len;
	read(new_socket, &tag_len, sizeof(size_t));

     size_t cphr_size;
	read(new_socket, &cphr_size, sizeof(size_t));

	//Receive Client Buffer and its size
	size_t final_size;
	read(new_socket, &final_size, sizeof(size_t));

    cout<<"\nFile_len: "<<file_len1<<"\n tag_len: "<<tag_len<<"\n cphr_size: "<<cphr_size<<"\n final_size: "<<final_size<<endl;
	unsigned char* final_buf = (unsigned char*)malloc(final_size);

      size_t chunk_size = 1024; // Adjust this to match the client's chunk size

      if(chunk_size>final_size)
      {
         read(new_socket, final_buf, final_size);
      }
      else
      {
            
        int total_bytes_received = 0;

        while (total_bytes_received < final_size) {
            int remaining_bytes = final_size - total_bytes_received;
            int bytes_to_receive = (remaining_bytes < chunk_size) ? remaining_bytes : chunk_size;

            int received = read(new_socket, final_buf + total_bytes_received, bytes_to_receive);
            if (received < 0) {
                perror("Error receiving data");
                free(final_buf); // Don't forget to free allocated memory
                exit(1);
            } else if (received == 0) {
                // Connection closed by the sender
                break;
            }

            total_bytes_received += received;
        }
      }
 
	// read(new_socket, cphr_buf, cphr_size);

	

	// unsigned char* tag_buf = (unsigned char*)malloc(tag_len);
	// read(new_socket, tag_buf, tag_len);


unsigned char* iv = (unsigned char*)malloc(EVP_CIPHER_iv_length(cipher));
unsigned char* cphr_buf = (unsigned char*)malloc(cphr_size);
unsigned char* tag_buf = (unsigned char*)malloc(tag_len);

// Extract iv
memcpy(iv, final_buf, EVP_CIPHER_iv_length(cipher));

// Extract cphr_buf
memcpy(cphr_buf, final_buf + EVP_CIPHER_iv_length(cipher), cphr_size);

// Extract tag_buf
memcpy(tag_buf, final_buf + EVP_CIPHER_iv_length(cipher) + cphr_size, tag_len);




   unsigned char* clear_buf = (unsigned char*)malloc(cphr_size);
   if(!clear_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
   cout<<"/n this is cphr size"<<cphr_size<<endl;

    cout<<"tag buf:"<<endl;
   //BIO_dump_fp (stdout, (const char *)tag_buf, tag_len);

   //Create and initialise the context
      EVP_CIPHER_CTX *ctx;
    int len=0;
    int plaintext_len=0;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("CIPHER_CTX_new");
    if(!EVP_DecryptInit(ctx, cipher, key, iv))
        handleErrors("EVP_DecryptInit");
	//Provide any AAD data.
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors("EVP_DecryptUpdate");
	//Provide the message to be decrypted, and obtain the plaintext output.
  int x=0;

   while((plaintext_len<(cphr_size-8)) && cphr_size>8){
        if( 1!= EVP_DecryptUpdate(ctx, clear_buf + plaintext_len, &len, cphr_buf + plaintext_len, 8)){
            perror("Errore: EVP_EncryptUpdate\n");
            exit(-1);
        }
        plaintext_len += len;
        cphr_size -= len;
        // x++;
    }
    cout<<"/n after update"<<plaintext_len<<endl;
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

   

   // write the plaintext into a '.dec' file:
   string clear_file_name = cphr_file_name;
   FILE* clear_file = fopen(("./Server/storage/"+uname+"/"+clear_file_name).c_str(), "wb");
   if(!clear_file) { cerr << "Error: cannot open file '" << clear_file_name << "' (no permissions?)\n"; exit(1); }
   ret = fwrite(clear_buf, 1, clear_size, clear_file);
   if(ret < clear_size) { cerr << "Error while writing the file '" << clear_file_name << "'\n"; exit(1); }
   fclose(clear_file);

   
   // Extract the sizes
    size_t extracted_size_file_size;
    int offset = 0;
    memcpy(&extracted_size_file_size, aad + offset, sizeof(size_t));
    offset += sizeof(size_t);
    
    size_t extracted_size_counter;
    memcpy(&extracted_size_counter, aad + offset, sizeof(size_t));
    offset += sizeof(extracted_size_counter);
    size_t extracted_size_operation_type;
    memcpy(&extracted_size_operation_type, aad + offset, sizeof(size_t));
    
    // size_t extracted_size_operation_type= sizeof(string);

    // Extract and print the data
    // printf("Extracted File Size: %zu\n", extracted_size_file_size);
    // printf("Extracted Counter: %zu\n", extracted_size_counter);
    //  printf("Extracted operation_type: %zu\n", extracted_size_operation_type);

   // delete the plaintext from memory:
   // Telling the compiler it MUST NOT optimize the following instruction. 
   // With optimization the memset would be skipped, because of the next free instruction.
#pragma optimize("", off)
   memset(clear_buf, 0, clear_size);
#pragma optimize("", on)
   free(clear_buf);

   cout << "File '"<< cphr_file_name << "' decrypted into file '" << clear_file_name << "', clear size is " << clear_size << " bytes\n";

   // deallocate buffers:
   free(iv);
   free(tag_buf);
   free(cphr_buf);
   free(file_name1);
   free(aad);
   free(final_buf);
   free(key);
//    free(key);
}