// Client side C/C++ program to demonstrate Socket
// programming
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h> // for error descriptions
#include <sys/types.h>
#include <dirent.h>

using namespace std;

static DH *get_dh2048_auto(void)
    {
        static unsigned char dhp_2048[] = {
            0xF9, 0xEA, 0x2A, 0x73, 0x80, 0x26, 0x19, 0xE4, 0x9F, 0x4B,
            0x88, 0xCB, 0xBF, 0x49, 0x08, 0x60, 0xC5, 0xBE, 0x41, 0x42,
            0x59, 0xDB, 0xEC, 0xCA, 0x1A, 0xC9, 0x90, 0x9E, 0xCC, 0xF8,
            0x6A, 0x3B, 0x60, 0x5C, 0x14, 0x86, 0x19, 0x09, 0x36, 0x29,
            0x39, 0x36, 0x21, 0xF7, 0x55, 0x06, 0x1D, 0xA3, 0xED, 0x6A,
            0x16, 0xAB, 0xAA, 0x18, 0x2B, 0x29, 0xE9, 0x64, 0x48, 0x67,
            0x88, 0xB4, 0x80, 0x46, 0xFD, 0xBF, 0x47, 0x17, 0x91, 0x4A,
            0x9C, 0x06, 0x0A, 0x58, 0x23, 0x2B, 0x6D, 0xF9, 0xDD, 0x1D,
            0x93, 0x95, 0x8F, 0x76, 0x70, 0xC1, 0x80, 0x10, 0x4B, 0x3D,
            0xAC, 0x08, 0x33, 0x7D, 0xDE, 0x38, 0xAB, 0x48, 0x7F, 0x38,
            0xC4, 0xA6, 0xD3, 0x96, 0x4B, 0x5F, 0xF9, 0x4A, 0xD7, 0x4D,
            0xAE, 0x10, 0x2A, 0xD9, 0xD3, 0x4A, 0xF0, 0x85, 0x68, 0x6B,
            0xDE, 0x23, 0x9A, 0x64, 0x02, 0x2C, 0x3D, 0xBC, 0x2F, 0x09,
            0xB3, 0x9E, 0xF1, 0x39, 0xF6, 0xA0, 0x4D, 0x79, 0xCA, 0xBB,
            0x41, 0x81, 0x02, 0xDD, 0x30, 0x36, 0xE5, 0x3C, 0xB8, 0x64,
            0xEE, 0x46, 0x46, 0x5C, 0x87, 0x13, 0x89, 0x85, 0x7D, 0x98,
            0x0F, 0x3C, 0x62, 0x93, 0x83, 0xA0, 0x2F, 0x03, 0xA7, 0x07,
            0xF8, 0xD1, 0x2B, 0x12, 0x8A, 0xBF, 0xE3, 0x08, 0x12, 0x5F,
            0xF8, 0xAE, 0xF8, 0xCA, 0x0D, 0x52, 0xBC, 0x37, 0x97, 0xF0,
            0xF5, 0xA7, 0xC3, 0xBB, 0xC0, 0xE0, 0x54, 0x7E, 0x99, 0x6A,
            0x75, 0x69, 0x17, 0x2D, 0x89, 0x1E, 0x64, 0xE5, 0xB6, 0x99,
            0xCE, 0x84, 0x08, 0x1D, 0x89, 0xFE, 0xBC, 0x80, 0x1D, 0xA1,
            0x14, 0x1C, 0x66, 0x22, 0xDA, 0x35, 0x1D, 0x6D, 0x53, 0x98,
            0xA8, 0xDD, 0xD7, 0x5D, 0x99, 0x13, 0x19, 0x3F, 0x58, 0x8C,
            0x4F, 0x56, 0x5B, 0x16, 0xE8, 0x59, 0x79, 0x81, 0x90, 0x7D,
            0x7C, 0x75, 0x55, 0xB8, 0x50, 0x63
        };
        static unsigned char dhg_2048[] = {
            0x02
        };
        DH *dh = DH_new();
        BIGNUM *p, *g;

        if (dh == NULL)
            return NULL;
        p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
        g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
        if (p == NULL || g == NULL
                || !DH_set0_pqg(dh, p, NULL, g)) {
            DH_free(dh);
            BN_free(p);
            BN_free(g);
            return NULL;
        }
        return dh;
    }

    int handleErrors(string data){
      cout<<"\n An error occurred with: "<<data<<endl;
        exit(1);
    }

     void printHexWithAscii(const unsigned char* data, size_t size) {
        printf("\n");
    for (size_t i = 0; i < size; ++i) {
        printf("%02X ", data[i]);
    }
    printf("   ");
    printf("\n");
    for (size_t i = 0; i < size; ++i) {
        if (isprint(data[i])) {
            printf("%c", data[i]);
        } else {
            printf(".");
        }
    }
    printf("\n");
}

int cloudverify(int sock, unsigned char* Cloud_cert, size_t Cloud_cert_size, unsigned char* cloud_half_key, size_t Chalfkey_size, unsigned char* CDH_sgn, unsigned int CDH_sgn_size) {
	
    cout<<"\n\n\n\nCloud begining to verify !!!!!!!!!!\n\n\n";
    size_t ret; // used for return values


   // load the CA's certificate:
   string cacert_file_name = "CA_cert";
//    cout << "Cloud Please, type the PEM file containing CA Public certificate: ";
//    getline(cin, cacert_file_name);
//    if(!cin) { cerr << "Error during input\n"; exit(1); }
   FILE* cacert_file = fopen(("./Client/publickeys/"+cacert_file_name).c_str(), "r");
   if(!cacert_file){ cerr << "Error: cannot open file '" << cacert_file_name << "' (missing?)\n"; exit(1); }
   X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
   fclose(cacert_file);
   if(!cacert){ cerr << "Error: PEM_read_X509 returned NULL\n"; exit(1); }

   // load the CRL:
   string crl_file_name = "CA_crl";
//    cout << "Cloud Please, type the PEM file containing the CRL: ";
//    getline(cin, crl_file_name);
//    if(!cin) { cerr << "Error during input\n"; exit(1); }
   FILE* crl_file = fopen(("./Client/publickeys/"+crl_file_name).c_str(), "r");
   if(!crl_file){ cerr << "Error: cannot open file '" << crl_file_name << "' (missing?)\n"; exit(1); }
   X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
   fclose(crl_file);
   if(!crl){ cerr << "Error: PEM_read_X509_CRL returned NULL\n"; exit(1); }

   // build a store with the CA's certificate and the CRL:
   X509_STORE* store = X509_STORE_new();
   if(!store) { cerr << "Error: X509_STORE_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_STORE_add_cert(store, cacert);
   if(ret != 1) { cerr << "Error: X509_STORE_add_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_STORE_add_crl(store, crl);
   if(ret != 1) { cerr << "Error: X509_STORE_add_crl returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
   if(ret != 1) { cerr << "Error: X509_STORE_set_flags returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }


    //  cout<<"\n Cloud Cert is:"<<endl;
    //  BIO_dump_fp (stdout, (char* )Cloud_cert, Cloud_cert_size);
    X509* cert;
    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio,Cloud_cert,Cloud_cert_size);
    cert = PEM_read_bio_X509(mbio,NULL,NULL,NULL);
    // const unsigned char *temp_cert_ptr = Cloud_cert;
    // cert = d2i_X509(NULL, &temp_cert_ptr, Cloud_cert_size);


   
   // verify the certificate:
   X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
   if(!certvfy_ctx) { cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_STORE_CTX_init(certvfy_ctx, store, cert, NULL);
   if(ret != 1) { cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_verify_cert(certvfy_ctx);
   //if(ret != 1) { cerr << "Error: X509_verify_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }

    if(ret != 1) 
    {
        cerr << "Error: X509_verify_cert returned " << ret << "\n";
        
        int err = X509_STORE_CTX_get_error(certvfy_ctx);
        const char* err_str = X509_verify_cert_error_string(err);
        
        cerr << "Detailed error: " << err_str << "\n";

        // Also print out the offending certificate if any
        X509* offending_cert = X509_STORE_CTX_get_current_cert(certvfy_ctx);
        if(offending_cert) {
            cerr << "Offending certificate:\n";
            //X509_print_ex(outbio, offending_cert, XN_FLAG_COMPAT, X509_FLAG_NO_EXTENSIONS);
        }

        exit(1);
    }


   // print the successful verification to screen:
   char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
   char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
   cout << "Certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully\n";
   free(tmp);
   free(tmp2);

   
    // cout<<"\n"
    // BIO_dump_fp (stdout, (unsigned char *)cloud_half_key, Chalfkey_size);
    cout<<"\nSigned buffer"<<endl;
    BIO_dump_fp (stdout, (unsigned char *)CDH_sgn, CDH_sgn_size);

   // create the signature context:
    const EVP_MD* md = EVP_sha256();
   EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
   if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

   // verify the plaintext:
   // (perform a single update on the whole plaintext, 
   // assuming that the plaintext is not huge)
   ret = EVP_VerifyInit(md_ctx, md);
   if(ret == 0){ cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; exit(1); }
   ret = EVP_VerifyUpdate(md_ctx, cloud_half_key, Chalfkey_size);  
   if(ret == 0){ cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n"; exit(1); }
   ret = EVP_VerifyFinal(md_ctx, CDH_sgn, CDH_sgn_size, X509_get_pubkey(cert));
   if(ret == -1){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
      cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
      exit(1);
   }else if(ret == 0){
      cerr << "Error: Invalid signature!\n";
      exit(1);
   }

   // print the successful signature verification to screen:
   cout << "The Signature has been correctly verified! The message is authentic!\n";

   // deallocate data:
   EVP_MD_CTX_free(md_ctx);
   X509_free(cert);
   X509_STORE_free(store);
   //X509_free(cacert); // already deallocated by X509_STORE_free()
   //X509_CRL_free(crl); // already deallocated by X509_STORE_free()
   X509_STORE_CTX_free(certvfy_ctx);
   delete[] cloud_half_key;
   delete[] CDH_sgn;
   delete[] Cloud_cert;

   return 0;
}



unsigned char authenticate(int sock)
{
//Take the username of the Client

std::string username;
size_t len_user, ret;
cout << "\nEnter Your Username: ";
getline(cin, username);
len_user = username.length();


//Client Generate it Nonce

	cout<<"Creating new client nonce . . ."<<endl;
	RAND_poll();
    const size_t NONCE_LEN = 16;
	//unsigned char client_nounce[16];
	unsigned char* client_nonce = nullptr;
    try {
        client_nonce = new unsigned char[NONCE_LEN];
    } catch (std::bad_alloc& e) {
        std::cerr << "Memory allocation failed: " << e.what() << std::endl;
        return 1; // Indicate failure to the caller
    }
	size_t rc = RAND_bytes(client_nonce, NONCE_LEN);
	size_t client_nonce_size= NONCE_LEN;
	
	if (rc != 1) {
    size_t err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    fprintf(stderr, "Random number generation error: %s\n", err_buf);
    exit(1);
    }


    cout<<"\n Client Nonce size:"<<client_nonce_size<<endl;
    cout<<"\n Client Nonce is:"<<endl;
    //printHexWithAscii(client_nonce,client_nonce_size);
    //BIO_dump_fp(stdout, client_nonce, client_nonce_size);
    cout<<"\n The Username is:"<<username<<endl;

    //Send client nonce with the username
    unsigned char* message1 = nullptr;
    try {
        message1 = new unsigned char[client_nonce_size + len_user];
    } catch (std::bad_alloc& e) {
        std::cerr << "Memory allocation failed: " << e.what() << std::endl;
        return 1; // Indicate failure to the caller
    }
   

    //Both Nonce and Username will be concatenated
    memcpy(message1, client_nonce, client_nonce_size);
    memcpy(message1 + client_nonce_size, username.c_str(), len_user);
    //message1[client_nonce_size + len_user] = '\0';

    //BIO_dump_fp(stdout, message1, (client_nonce_size + len_user));
    //Send the sizes of the variables

    // cout<<"\n Size of client nonce: "<<client_nonce_size<<endl;
    // cout<<"\n Size of client len: "<<len_user<<endl;
    ret = send(sock, &client_nonce_size, sizeof(size_t), 0);
    if(ret == -1)
    {
        handleErrors("Client Nonce Size");
    }
    ret = send(sock, &len_user, sizeof(size_t), 0);
    if(ret == -1)
    {
        handleErrors("Client Len Size");
    }

    //Now send the message M1
    ret = send(sock, message1, (client_nonce_size + len_user), 0);
    if(ret == -1)
    {
        handleErrors("Client Message M1");
    }
     delete[] message1;
   

    //Waiting for Message M2 from Server
    cout<<"\n Waiting for Message M2 from Server"<<endl;
   
   //Receive Cloud cert and cert size
    //uint16_t lmsg;
    size_t Cloud_cert_size;// = ntohs(lmsg);
    ret = read(sock, &Cloud_cert_size, sizeof(size_t));
    if(ret < sizeof(size_t)){
        perror("\nError receiving the cert size\n");
        exit(-1);
    }
    

    
    // cout<<"\n Cloud Cert size: "<<Cloud_cert_size<<endl;
    unsigned char* Cloud_cert = nullptr;
    try {
        Cloud_cert = new unsigned char[Cloud_cert_size];
    } catch (std::bad_alloc& e) {
        std::cerr << "Memory allocation CDH_clear failed: " << e.what() << std::endl;
        return 1; // Indicate failure to the caller
    }
    //  try {
    //     Cloud_cert = new unsigned char[Cloud_cert_size];
    // } catch (std::bad_alloc& e) {
    //     std::cerr << "Memory allocation failed: " << e.what() << std::endl;
    //     return 1; // Indicate failure to the caller
    // }

    ret = read(sock,Cloud_cert,(Cloud_cert_size+1));
    if(ret < Cloud_cert_size){
        perror("\nError receiving the cert\n");
        exit(-1);
    }

    //  cout<<"\n Cert buffer"<<endl;
    // BIO_dump_fp (stdout, Cloud_cert, (Cloud_cert_size+1));

    //Receive cloud clear and signed buffers sizes
    size_t CDH_clear_size, Cloud_Nonce_size;
    unsigned int CDH_sgn_size;

   ret = read(sock, &CDH_clear_size, sizeof(size_t));
   if(ret < sizeof(size_t)){
    cout<<"\n Ret: "<<ret<<endl;
        if (ret == -1) {
        perror("\nError reading CDH_sgn_size\n");
    } else {
        fprintf(stderr, "\nIncomplete read for CDH_sgn_size\n");
    }
        exit(-1);
    }
   ret = read(sock, &CDH_sgn_size, sizeof(unsigned int));
   if(ret < sizeof(unsigned int)){
        perror("\nError receiving CDH_sgn_size\n");
        exit(-1);
    }

    // cout<<"\n CDH_sgn_size: "<<CDH_sgn_size<<endl;
    // cout<<"\n CDH_clear: "<<CDH_clear_size<<endl;

    //Receive Cloud clear half key and signed half key with client nonce
    unsigned char* CDH_clear = nullptr;
    try {
        CDH_clear = new unsigned char[CDH_clear_size];
    } catch (std::bad_alloc& e) {
        std::cerr << "Memory allocation CDH_clear failed: " << e.what() << std::endl;
        return 1; // Indicate failure to the caller
    }
    
    unsigned char* CDH_sgn = nullptr;
    try {
        CDH_sgn = new unsigned char[CDH_sgn_size];
    } catch (std::bad_alloc& e) {
        std::cerr << "Memory allocation CDH_sgn failed: " << e.what() << std::endl;
        return 1; // Indicate failure to the caller
    }

    ret = read(sock, CDH_clear, CDH_clear_size);
     if(ret < CDH_clear_size){
        perror("\nError receiving CDH_clear\n");
        exit(-1);
    }
    //  cout<<"\n CDH_clear buffer"<<endl;
    // BIO_dump_fp (stdout, CDH_clear, CDH_clear_size);

    ret = read(sock, CDH_sgn, CDH_sgn_size);
     if(ret < CDH_sgn_size){
        cout<<"\n Ret: "<<ret<<endl;
        perror("\nError receiving CDH_sgn\n");
        exit(-1);
    }

    //Receive Cloud Nonce and Size
    unsigned char* Cloud_nonce = nullptr;
    try {
        Cloud_nonce = new unsigned char[Cloud_Nonce_size];
    } catch (std::bad_alloc& e) {
        std::cerr << "Memory allocation Cloud_nonce failed: " << e.what() << std::endl;
        return 1; // Indicate failure to the caller
    }
   ret = read(sock, &Cloud_Nonce_size, sizeof(size_t));
   if(ret < sizeof(size_t)) {
        perror("\nError receiving Cloud_Nonce_size\n");
        exit(-1);
    }
    ret = read(sock, Cloud_nonce, Cloud_Nonce_size);
     if(ret < Cloud_Nonce_size){
        perror("\nError receiving Cloud_nonce\n");
        exit(-1);
    }

    cout<<"\n Message M2 Received"<<endl;

    cout<<"\n Verifying Message M2"<<endl;
    
    //Concatenate the Cloud half key and the cloud nonce
    size_t Chalfkey_size = client_nonce_size + CDH_clear_size;
    unsigned char* cloud_half_key = nullptr;
    try {
        cloud_half_key = new unsigned char[Chalfkey_size];
    } catch (std::bad_alloc& e) {
        std::cerr << "Memory allocation failed: " << e.what() << std::endl;
        return 1; // Indicate failure to the caller
    }
    
    memcpy(cloud_half_key , CDH_clear, CDH_clear_size);
    memcpy(cloud_half_key + CDH_clear_size, client_nonce, client_nonce_size);

    // cout<<"\n Concatenated buffer"<<endl;
    // BIO_dump_fp (stdout, cloud_half_key, Chalfkey_size);

    //  cout<<"\n Cert buffer"<<endl;
    // BIO_dump_fp (stdout, Cloud_cert, Cloud_cert_size);
    
    cout<<"\n Before verify"<<endl;

    //Client Veify cloud signed Public DH key
    cloudverify(sock, Cloud_cert, Cloud_cert_size, cloud_half_key, Chalfkey_size, CDH_sgn, CDH_sgn_size);
      
       delete[] client_nonce;
      

     cout<<"\n Generating Message M3"<<endl;

    
    delete[] Cloud_nonce;
    delete[] CDH_clear;
    
    
 

    return 0;
}