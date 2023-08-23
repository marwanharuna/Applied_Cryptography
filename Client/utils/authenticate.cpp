
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

    int handleErrors(){
        printf("An error occourred.\n");
        exit(1);
    }



int signclient(int sock) {

	cout<<"\n\n\n\nClient begining to sign !!!!!!!!!!\n\n\n";
	
	//Generate new client nonce

	cout<<"Creating new client nonce . . ."<<endl;
	RAND_poll();
        int NONCE_LEN = 16;
	//unsigned char client_nounce[16];
	  unsigned char* client_nonce =  new unsigned char[NONCE_LEN];
	int rc = RAND_bytes(client_nonce, sizeof(client_nonce));
	long int client_nonce_size= sizeof(client_nonce);
	
	  
	unsigned long err = ERR_get_error();
	if(rc != 1)
	{
		exit(1);
	}

   // read my private key file from keyboard:
   string prvkey_file_name;
   cout << "Please, type the PEM file containing Client private key: ";
   getline(cin, prvkey_file_name);
   if(!cin) { cerr << "Error during input\n"; exit(1); }

   // load my private key:
   FILE* prvkey_file = fopen(("local/keys/"+prvkey_file_name).c_str(), "r");
   if(!prvkey_file){ cerr << "Error: cannot open file '" << prvkey_file_name << "' (missing?)\n"; exit(1); }
   EVP_PKEY* prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
   fclose(prvkey_file);
   if(!prvkey){ cerr << "Error: PEM_read_PrivateKey returned NULL\n"; exit(1); }

   // read the file to sign from keyboard:
   string clear_file_name;
   cout << "Please, type the Client file to sign: ";
   getline(cin, clear_file_name);
   if(!cin) { cerr << "Error during input\n"; exit(1); }

   // open the file to sign:
   FILE* clear_file = fopen(("local/temp/"+clear_file_name).c_str(), "rb");
   if(!clear_file) { cerr << "Error: cannot open file '" << clear_file_name << "' (file does not exist?)\n"; exit(1); }

   // get the file size: 
   // (assuming no failures in fseek() and ftell())
   fseek(clear_file, 0, SEEK_END);
   long int clear_size = ftell(clear_file);
   fseek(clear_file, 0, SEEK_SET);

   // read the plaintext from file:
   unsigned char* clear_buf = (unsigned char*)malloc(clear_size);
   if(!clear_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
   int ret = fread(clear_buf, 1, clear_size, clear_file);
   if(ret < clear_size) { cerr << "Error while reading file '" << clear_file_name << "'\n"; exit(1); }
   fclose(clear_file);
    
   // declare some useful variables:
   const EVP_MD* md = EVP_sha256();

   // create the signature context:
   EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
   if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

   // allocate buffer for signature:
   unsigned char* sgnt_buf = (unsigned char*)malloc(EVP_PKEY_size(prvkey));
   if(!sgnt_buf) { cerr << "Error: malloc returned NULL (signature too big?)\n"; exit(1); }

   // sign the plaintext:
   // (perform a single update on the whole plaintext, 
   // assuming that the plaintext is not huge)
   ret = EVP_SignInit(md_ctx, md);
   if(ret == 0){ cerr << "Error: EVP_SignInit returned " << ret << "\n"; exit(1); }
   ret = EVP_SignUpdate(md_ctx, clear_buf, clear_size);
   if(ret == 0){ cerr << "Error: EVP_SignUpdate returned " << ret << "\n"; exit(1); }
   unsigned int sgnt_size;
   ret = EVP_SignFinal(md_ctx, sgnt_buf, &sgnt_size, prvkey);
   if(ret == 0){ cerr << "Error: EVP_SignFinal returned " << ret << "\n"; exit(1); }

   // delete the digest and the private key from memory:
   EVP_MD_CTX_free(md_ctx);
   EVP_PKEY_free(prvkey);

   // write the signature into a '.sgn' file:
   string sgnt_file_name = clear_file_name + ".sgn";
   FILE* sgnt_file = fopen(("local/temp/"+sgnt_file_name).c_str(), "wb");
   if(!sgnt_file) { cerr << "Error: cannot open file '" << sgnt_file_name << "' (no permissions?)\n"; exit(1); }
   ret = fwrite(sgnt_buf, 1, sgnt_size, sgnt_file);
   if(ret < sgnt_size) { cerr << "Error while writing the file '" << sgnt_file_name << "'\n"; exit(1); }
   fclose(sgnt_file);
   BIO_dump_fp (stdout, (const char *)sgnt_buf, sizeof(sgnt_buf));
   cout << "File '"<< clear_file_name << "' signed into file '" << sgnt_file_name << "'\n";

    
    




	//send buffer through socket ADHpublic and ADHpublic.sng

	//sending size of clear buf and signed buf
	cout<<"\n Clear size is:"<<clear_size<<" sgnt size is:"<<sgnt_size<<endl;
	send(sock, (long int*)&clear_size, sizeof(long int), 0);
	printf("Client Clear size to cloud\n");
	send(sock, (unsigned int*)&sgnt_size, sizeof(unsigned int), 0);
	printf("Client Public key Sent to cloud\n");
   	

	//sending clear buf and signed buf
    
	send(sock,clear_buf, clear_size, 0);
	printf("\nClient Public key Sent to cloud\n");
   	send(sock,sgnt_buf, sgnt_size, 0);
	printf("Client signed public key sent to cloud\n");

	//sending nonce
	send(sock, (long int*)&client_nonce_size, sizeof(long int), 0);
	printf("Client nounce size  Sent to cloud\n");
	cout<<"Client side: Client Nounce before sending"<<client_nonce<<endl;
	send(sock,client_nonce, client_nonce_size, 0);
	printf("Client nounce sent to cloud\n");

	// Receive Cloud buffer through socket

	//reading cloud size of clear buf and signed buf
	int val1, val2,val3,val4;
	unsigned int cloud_sgnt_buf_size;
	long int cloud_clear_buf_size;
	val1 = read(sock, (long int*)&cloud_clear_buf_size, sizeof(long int));
	val2 = read(sock, (unsigned int*)&cloud_sgnt_buf_size, sizeof(unsigned int));
	cout<<"\n Cloud Clear size is:"<<cloud_clear_buf_size<<" cloud Sgnt size is:"<<cloud_sgnt_buf_size<<endl;

	//reading cloud clear buf and signed buf
	unsigned char* cloud_clear_buf = (unsigned char*)malloc(cloud_clear_buf_size);
	unsigned char* cloud_sgnt_buf = (unsigned char*)malloc(cloud_sgnt_buf_size);
   	int valread1 = read(sock, cloud_clear_buf, cloud_clear_buf_size);
  	int valread2 = read(sock, cloud_sgnt_buf, cloud_sgnt_buf_size);
	
	
	 // recieving cloud nounce 
  	 
  	 long int c_to_client_size;
	val1 = read(sock, (long int*)&c_to_client_size, sizeof(long int));
	unsigned char * cloud_nounce  = (unsigned char*)malloc(c_to_client_size);
  	 int valread3 = read(sock,cloud_nounce,c_to_client_size);
  	 cout<<"\n\n\n\nCloud nounce recieved from cloud:"<<cloud_nounce;
  	 
  	 // recieving client nounce 
  	 
  	 long int c_to_cloud_size1;
	val2 = read(sock, (long int*)&c_to_cloud_size1, sizeof(long int));
	unsigned char * client_nounce1  = (unsigned char*)malloc(c_to_cloud_size1);
  	 int valread4 = read(sock,client_nounce1,c_to_cloud_size1);
  	 cout<<"\n\n\n\nClient nounce back :"<<client_nounce1;
  	 cout<<"\n\n\n\nClient nounce:"<<client_nonce;
  	 
	//sending cloud nonce back 
	send(sock, (long int*)&c_to_client_size, sizeof(long int), 0);
	printf("Cloud nounce size  Sent to cloud\n");
	cout<<"Client side: Cloud Nounce before sending"<<cloud_nounce<<endl;
	send(sock,cloud_nounce, c_to_client_size, 0);
	printf("Cloud nounce sent to cloud back\n");

  	 // cout<<sizeof(client_nounce1)<<"\n\n\n\nCloud nounce1 \n\n\n";
  	 // cout<<sizeof(client_nonce)<<"\n\n\n\nCloud nounce \n\n\n";
  	  int x= sizeof(client_nonce);
  	 if(memcmp(client_nounce1,client_nonce,sizeof(unsigned char))==0){
	  
	  cout<< "\n client nounce is the same\n";
	  //client_nounce++;
	
	  }

          else{
          
           cout<< "\n client nounce is not the same\n";
           //exit(1);
           
          }
  	 
  	 
  	 
  	
	
	// Save the Client DHkey  file:
	   string sgnt_file_name1 = "CloudDH";
	   FILE* sgnt_file1 = fopen(("local/Cloud_DHkeys/"+sgnt_file_name1).c_str(), "wb");
	   if(!sgnt_file1) { cerr << "Error: cannot open file '" << sgnt_file_name1 << "' (no permissions?)\n"; exit(1); }
	   ret = fwrite(cloud_clear_buf, 1, cloud_clear_buf_size, sgnt_file1);
	   if(ret < cloud_clear_buf_size) { cerr << "Error while writing the file '" << sgnt_file_name1 << "'\n"; exit(1); }
	   fclose(sgnt_file1);
	 //Save the Client signed DHkey  file into a '.sgn' file:
	   string sgnt_file_name2 = "CloudDH.sgn";
	   FILE* sgnt_file2 = fopen(("local/Cloud_DHkeys/"+sgnt_file_name2).c_str(), "wb");
	   if(!sgnt_file2) { cerr << "Error: cannot open file '" << sgnt_file_name2 << "' (no permissions?)\n"; exit(1); }
	   ret = fwrite(cloud_sgnt_buf, 1, cloud_sgnt_buf_size, sgnt_file2);
	   if(ret < cloud_sgnt_buf_size) { cerr << "Error while writing the file '" << sgnt_file_name2 << "'\n"; exit(1); }
	   fclose(sgnt_file2);
    
   // deallocate buffers:
   free(cloud_clear_buf);
   free(cloud_sgnt_buf);


   return 0;
}


int cloudverify(int sock, unsigned char* server_cert, long server_cert_size, unsigned char* cloud_half_key, unsigned int Chalfkey_size, unsigned char* CDH_sgn, unsigned int CDH_sgn_size) {
	cout<<"\n\n\n\nCloud begining to verify !!!!!!!!!!\n\n\n";
	
	
   int ret; // used for return values


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

   // load the peer's certificate:
//    string cert_file_name;
//    cout << "Clients Please, type the PEM file containing Cloud peer's certificate: ";
//    getline(cin, cert_file_name);
//    if(!cin) { cerr << "Error during input\n"; exit(1); }
//    FILE* cert_file = fopen(("publickeys/"+cert_file_name).c_str(), "r");
//    if(!cert_file){ cerr << "Error: cannot open file '" << cert_file_name << "' (missing?)\n"; exit(1); }

    //  cout<<"\n Cloud Cert is:"<<endl;
    //  BIO_dump_fp (stdout, (char* )server_cert, server_cert_size);
    X509* cert;
    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio,server_cert,server_cert_size);
    cert = PEM_read_bio_X509(mbio,NULL,NULL,NULL);
    // const unsigned char *temp_cert_ptr = server_cert;
    // cert = d2i_X509(NULL, &temp_cert_ptr, server_cert_size);

   //fclose(cert_file);
   //if(!cert){ cerr << "Error: PEM_read_X509 returned NULL\n"; exit(1); }

//    cout<<"\n Cloud Cert is:"<<endl;
//     // Print the certificate details
//     BIO* outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
//     if(!outbio) { cerr << "Error: Unable to create BIO for stdout\n"; exit(1); }

   // X509_print_ex(outbio, cert, XN_FLAG_COMPAT, X509_FLAG_NO_EXTENSIONS);
   
   // verify the certificate:
   X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
   if(!certvfy_ctx) { cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_STORE_CTX_init(certvfy_ctx, store, cert, NULL);
   if(ret != 1) { cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_verify_cert(certvfy_ctx);
   //if(ret != 1) { cerr << "Error: X509_verify_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }

    if(ret != 1) {
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

//    // load the signature file:
//    string sgnt_file_name = "";
//    cout << "Client Please, type the Cloud signature file: ";
//    getline(cin, sgnt_file_name);
//    if(!cin) { cerr << "Error during input\n"; exit(1); }
//    FILE* sgnt_file = fopen(("local/Cloud_DHkeys/"+sgnt_file_name).c_str(), "rb");
//    if(!sgnt_file) { cerr << "Error: cannot open file '" << sgnt_file_name << "' (file does not exist?)\n"; exit(1); }

//    // get the file size: 
//    // (assuming no failures in fseek() and ftell())
//    fseek(sgnt_file, 0, SEEK_END);
//    long int sgnt_size = ftell(sgnt_file);
//    fseek(sgnt_file, 0, SEEK_SET);

//    // read the signature from file:
//    unsigned char* sgnt_buf = (unsigned char*)malloc(sgnt_size);
//    if(!sgnt_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
//    ret = fread(sgnt_buf, 1, sgnt_size, sgnt_file);
//    if(ret < sgnt_size) { cerr << "Error while reading file '" << sgnt_file_name << "'\n"; exit(1); }
//    fclose(sgnt_file);
//     BIO_dump_fp (stdout, (const char *)sgnt_buf, sizeof(sgnt_buf));
   // declare some useful variables:

//    // read the file to verify from keyboard:
//    string clear_file_name;
//    cout << "Client Please, type the Cloud file to verify: ";
//    getline(cin, clear_file_name);
//    if(!cin) { cerr << "Error during input\n"; exit(1); }

//    // open the file to verify:
//    FILE* clear_file = fopen(("local/Cloud_DHkeys/"+clear_file_name).c_str(), "rb");
//    if(!clear_file) { cerr << "Error: cannot open file '" << clear_file_name << "' (file does not exist?)\n"; exit(1); }

//    // get the file size: 
//    // (assuming no failures in fseek() and ftell())
//    fseek(clear_file, 0, SEEK_END);
//    long int clear_size = ftell(clear_file);
//    fseek(clear_file, 0, SEEK_SET);

//    // read the plaintext from file:
//    unsigned char* clear_buf = (unsigned char*)malloc(clear_size);
//    if(!clear_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
//    ret = fread(clear_buf, 1, clear_size, clear_file);
//    if(ret < clear_size) { cerr << "Error while reading file '" << clear_file_name << "'\n"; exit(1); }
//    fclose(clear_file);
//     BIO_dump_fp (stdout, (const char *)sgnt_buf, sizeof(sgnt_buf));
   
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
   free(cloud_half_key);
   free(CDH_sgn);

   return 0;
}

unsigned char authenticate(int sock)
{
//Take the username of the Client

string username;
cout << "\nEnter Your Username: ";
getline(cin, username);
int len_user = username.length();


//Client Generate it Nonce

	cout<<"Creating new client nonce . . ."<<endl;
	RAND_poll();
        int NONCE_LEN = 16;
	//unsigned char client_nounce[16];
	  unsigned char* client_nonce =  new unsigned char[NONCE_LEN];
	int rc = RAND_bytes(client_nonce, NONCE_LEN);
	long int client_nonce_size= NONCE_LEN;
	
	  
	unsigned long err = ERR_get_error();
	if(rc != 1)
	{
		exit(1);
	}
    cout<<"\n Client Nonce size:"<<client_nonce_size<<endl;
    cout<<"\n Client Nonce is:"<<endl;
    BIO_dump_fp(stdout, client_nonce, client_nonce_size);
    cout<<"\n The Username is:"<<username<<endl;

    //Send client nonce with the username
    char message1[client_nonce_size + len_user + 1];


    //Both Nonce and Username will be concatenated
    memcpy(message1, client_nonce, client_nonce_size);
    memcpy(message1 + client_nonce_size, username.c_str(), len_user);
    message1[client_nonce_size + len_user] = '\0';


    //Send the sizes of the variables
    send(sock, &client_nonce_size, sizeof(long int), 0);
    send(sock, &len_user, sizeof(int), 0);

    //Now send the message M1
    send(sock, &message1, (client_nonce_size + len_user), 0);

    //send(sock, hello, strlen(hello), 0);

    //Waiting for Message M2 from Server
    cout<<"\n Waiting for Message M2 from Server"<<endl;

    //ricevo il certificato dal server e lo controllo
    uint16_t lmsg;
    int ret = read(sock,(void*)&lmsg,sizeof(uint16_t));
    if(ret < sizeof(uint16_t)){
        perror("\nError receiving the cert size\n");
        exit(-1);
    }
    long pubkey_size = ntohs(lmsg);
    unsigned char* pubkey_buf = new unsigned char[pubkey_size + 1];
    ret = read(sock,pubkey_buf,pubkey_size);
    pubkey_buf[pubkey_size] = '\0';
    if(ret < pubkey_size){
        perror("\nError receiving the cert\n");
        exit(-1);
    }

    //Receive cloud buffer sizes
    long int CDH_clear_size, Cloud_Nonce_size;
    unsigned int CDH_sgn_size;

   ret = read(sock,(void *)&CDH_clear_size,sizeof(long int));
   if(ret < sizeof(long int)){
        perror("\nError receiving CDH_clear_size\n");
        exit(-1);
    }
   ret = read(sock,(void *)&CDH_sgn_size,sizeof(unsigned int));
   if(ret < sizeof(unsigned int)){
        perror("\nError receiving CDH_sgn_size\n");
        exit(-1);
    }

    //Receive Cloud clear half key and signed half key with client nonce
    unsigned char* CDH_clear = new unsigned char[CDH_clear_size + 1];
    unsigned char* CDH_sgn = new unsigned char[CDH_sgn_size + 1];

    ret = read(sock,CDH_clear,CDH_clear_size);
     if(ret < CDH_clear_size){
        perror("\nError receiving CDH_clear\n");
        exit(-1);
    }
    ret = read(sock,CDH_sgn,CDH_sgn_size);
     if(ret < CDH_sgn_size){
        perror("\nError receiving CDH_sgn\n");
        exit(-1);
    }

    //Receive Cloud Nonce and Size
    unsigned char* Cloud_nonce = new unsigned char[Cloud_Nonce_size];
   ret = read(sock,(void*)&Cloud_Nonce_size,sizeof(long int));
   if(ret < sizeof(long int)){
        perror("\nError receiving Cloud_Nonce_size\n");
        exit(-1);
    }
    ret = read(sock,&Cloud_nonce,Cloud_Nonce_size);
     if(ret < Cloud_Nonce_size){
        perror("\nError receiving Cloud_nonce\n");
        exit(-1);
    }

    cout<<"\n Message M2 Received"<<endl;

    cout<<"\n Verifying Message M2"<<endl;
    //read(sock, &C_cert, sizeof(X509*));

   // cout<<"\n Cert size: "<<lmsg<<endl;
    //cout<<"\n Certificate: "<<endl;

    //BIO_dump_fp (stdout, (unsigned char* )pubkey_buf, pubkey_size);

    //  cout<<"\n Cloud half key clear buffer"<<endl;
    //  BIO_dump_fp (stdout, (const char *)CDH_clear, CDH_clear_size);

    //Concatenate the Cloud half key and the cloud nonce
    unsigned char* cloud_half_key = new unsigned char[client_nonce_size + CDH_clear_size];
    unsigned int Chalfkey_size = client_nonce_size + CDH_clear_size;
    memcpy(cloud_half_key , CDH_clear, CDH_clear_size);
    memcpy(cloud_half_key + CDH_clear_size, client_nonce, client_nonce_size);

    
   

    delete [] client_nonce;

    cout<<"\n Concatenated buffer"<<endl;
     BIO_dump_fp (stdout, (const char *)cloud_half_key, Chalfkey_size);
    
    cout<<"\n Before verify"<<endl;

    //Client Veify cloud signed Public DH key
    cloudverify(sock, pubkey_buf, pubkey_size, cloud_half_key, Chalfkey_size, CDH_sgn, CDH_sgn_size);

/*GENERATING MY EPHEMERAL KEY*/
/* Use built-in parameters */
printf("Start: loading standard DH parameters\n");
EVP_PKEY *params;// structure param// we pass empty params
if(NULL == (params = EVP_PKEY_new())) handleErrors();
DH* temp = get_dh2048_auto();
if(1 != EVP_PKEY_set1_DH(params,temp)) handleErrors();// to retrive the parameters inside your code and you use this fucniton to retirve the parameters inside the EVP_PKEY_set1_DH 
  //so pass empty EVP_pkey Param structure and this funciton   copies the values retrived from the command lien tool to the structured param
DH_free(temp);
printf("\n");
printf("Generating ephemeral DH KeyPair\n");
/* Create context for the key generation */// ready to generate the DH key pairs
EVP_PKEY_CTX *DHctx;
// initialize the context with params
if(!(DHctx = EVP_PKEY_CTX_new(params, NULL))) handleErrors();
/* Generate a new key */ //not drive a key, so the APi is KEYGEN_INIThj
EVP_PKEY *my_dhkey = NULL;
if(1 != EVP_PKEY_keygen_init(DHctx)) handleErrors();
if(1 != EVP_PKEY_keygen(DHctx, &my_dhkey)) handleErrors();// Generate a key which will be contained in the structure named EVP_PKEY NAMED MY MY_DHKEY  
// now we have in my_dhkey our private key which also contains the public key, with seralization API you will be able to extract from my_dhkey the public key to store inside the PEM FILE
/*write my public key into a file, so the other client can read it*/
//Get nonce
    //Generate new client nonce

//
string my_pubkey_file_name;
cout << "Please, type the PEM file that will contain clients DH public key: ";
getline(cin, my_pubkey_file_name);
if(!cin) { cerr << "Error during input\n"; exit(1); }
FILE* p1w = fopen(("./Client/local/temp/"+my_pubkey_file_name).c_str(), "w");
if(!p1w){ cerr << "Error: cannot open file '"<< my_pubkey_file_name << "' (missing?)\n"; exit(1); }
PEM_write_PUBKEY(p1w, my_dhkey);// to seralize and save
fclose(p1w);


string peer_pubkey_file_name;

/*Sign the client public key */
cout<<"\n Signing Client Diffie-Hellman Key \n";

signclient(sock);


// here is for cloud to sign its diffie hellman


cout << "Please, type the PEM file that contains the cloud's signed DH public key: ";
getline(cin, peer_pubkey_file_name);
if(!cin) { cerr << "Error during input\n"; exit(1); }
/*Load peer public key from a file*/
FILE* p2r = fopen(("local/Cloud_DHkeys/"+peer_pubkey_file_name).c_str(), "r");
if(!p2r){ cerr << "Error: cannot open file '"<< peer_pubkey_file_name <<"' (missing?)\n"; exit(1); }
EVP_PKEY* peer_pubkey = PEM_read_PUBKEY(p2r, NULL, NULL, NULL);//to load
fclose(p2r);
if(!peer_pubkey){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }

printf("Deriving a shared secret\n");// this time we are driving not generating 
/*creating a context, the buffer for the shared key and an int for its length*/
EVP_PKEY_CTX *derive_ctx;
unsigned char *skey;
size_t skeylen;
derive_ctx = EVP_PKEY_CTX_new(my_dhkey,NULL);// in the context new we pass the private my_dhkey generated before then we call the drive_init no the keygen_init
if (!derive_ctx) handleErrors();
if (EVP_PKEY_derive_init(derive_ctx) <= 0) handleErrors();
/*Setting the peer with its pubkey*/// so we continue to set the public key uploaded in memroy form the file of the peer and you can see peer_pubkey is already structured in EVP_PKEY
if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pubkey) <= 0) handleErrors();
/* Determine buffer length, by performing a derivation but writing the result nowhere */
EVP_PKEY_derive(derive_ctx, NULL, &skeylen);//  then we call the drive funciton. so we created and initilaizzed the context and we tell the material to the context the material with which he should work and then we command the context this manager of encryption of cryptographic operation what we want him to do  
//at line 122 we determine the buffer length also cuz the derivation of the DH the shared secret  can have a variable length.so open ssl gives us an option to determine exactly the number of bits to allocate in order to have precise buffer for the long derived shared secret 
/*allocate buffer for the shared secret*/
skey = (unsigned char*)(malloc(int(skeylen)));
if (!skey) handleErrors();
/*Perform again the derivation and store it in skey buffer*/
if (EVP_PKEY_derive(derive_ctx, skey, &skeylen) <= 0) handleErrors();
printf("Here it is the shared secret: \n");
BIO_dump_fp (stdout, (const char *)skey, skeylen);
/*WARNING! YOU SHOULD NOT USE THE DERIVED SECRET AS A SESSION KEY!
 * IS COMMON PRACTICE TO HASH THE DERIVED SHARED SECRET TO OBTAIN A SESSION KEY.
 */
//FREE EVERYTHING INVOLVED WITH THE EXCHANGE (not the shared secret tho)
EVP_PKEY_CTX_free(derive_ctx);
EVP_PKEY_free(peer_pubkey);
EVP_PKEY_free(my_dhkey);
EVP_PKEY_CTX_free(DHctx);
EVP_PKEY_free(params);


//////////////////////////////////////////////////
//												//
//	USING SHA-256 TO EXTRACT A SAFE KEY!		//
//												//
//////////////////////////////////////////////////
	

// Hashing the shared secret to obtain a key Client Side.
// Hashing the shared secret to obtain a key. and to increase the entropy of the shared secret key
//create digest pointer and length variable
unsigned char* digest;
unsigned int digestlen;	
// Create and init context
EVP_MD_CTX *Hctx;
Hctx = EVP_MD_CTX_new();	
//allocate memory for digest and this time we know how big the buffer is because it is output of hash function so 256 bit which is fixed
digest = (unsigned char*) malloc(EVP_MD_size(EVP_sha256()));	
//init, Update (only once) and finalize digest
EVP_DigestInit(Hctx, EVP_sha256());// declare hash funciton we want to use 
EVP_DigestUpdate(Hctx, (unsigned char*)skey, skeylen);// we send the input of the hash funciton 
EVP_DigestFinal(Hctx, digest, &digestlen); //the digest final will retrive the hash output and put in the declaed buffer digest
//REMEMBER TO FREE CONTEXT!!!!!!
EVP_MD_CTX_free(Hctx);
//Print digest to screen in hexadecimal
int n;
printf("Digest is:\n");
for(n=0;digest[n]!= '\0'; n++)
	printf("%02x", (unsigned char) digest[n]);
printf("\n");




}
