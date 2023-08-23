
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
#include <sys/shm.h>

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

int signcloud(int sock, unsigned char* client_Nonce1, long int client_nounce_size) {

cout<<"\n\n\n\nCloud begining to sign !!!!!!!!!!\n\n\n";
   int ret; // used for return values

	//Generate new client nonce

	cout<<"Creating new cloud nonce . . ."<<endl;
	RAND_poll();

	  int NONCE_LEN1 = 16;
	//unsigned char client_nounce[16];
	  unsigned char* cloud_nonce =  new unsigned char[NONCE_LEN1];
	int rc = RAND_bytes(cloud_nonce, NONCE_LEN1);
	long int cloud_nounce_size= sizeof(cloud_nonce);
	unsigned long err = ERR_get_error();
	if(rc != 1)
	{
		exit(1);
	}
    
    //Get Client Nonce
    char client_Nonce3[client_nounce_size];
    //memset(client_Nonce3, 0, client_nounce_size);
    memcpy(client_Nonce3, client_Nonce1, client_nounce_size);
    //client_Nonce3[client_nounce_size] = '\0';

    cout<<"\n Client nonce in sign:"<<endl;
   BIO_dump_fp (stdout, (unsigned char *)client_Nonce3, client_nounce_size);

   // read my private key file from keyboard:
   string prvkey_file_name = "Cprvkey.pem";
   cout << "Cloud Please, type the PEM file containing Cloud private key: ";
//    getline(cin, prvkey_file_name);
//    if(!cin) { cerr << "Error during input\n"; exit(1); }

   // load my private key:
   FILE* prvkey_file = fopen(("./Server/storage/keys/"+prvkey_file_name).c_str(), "r");
   if(!prvkey_file){ cerr << "Error: cannot open file '" << prvkey_file_name << "' (missing?)\n"; exit(1); }
   EVP_PKEY* prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
   fclose(prvkey_file);
   if(!prvkey){ cerr << "Error: PEM_read_PrivateKey returned NULL\n"; exit(1); }

   // read the file to sign from keyboard:
   string clear_file_name = "CDHpublic";
   cout << "Please, type the Cloud file to sign: ";
//    getline(cin, clear_file_name);
//    if(!cin) { cerr << "Error during input\n"; exit(1); }

   // open the file to sign:
   FILE* clear_file = fopen(("./Server/storage/keys/"+clear_file_name).c_str(), "rb");
   if(!clear_file) { cerr << "Error: cannot open file '" << clear_file_name << "' (file does not exist?)\n"; exit(1); }

   // get the file size: 
   // (assuming no failures in fseek() and ftell())
   fseek(clear_file, 0, SEEK_END);
   long int clear_size = ftell(clear_file);
   fseek(clear_file, 0, SEEK_SET);

   // read the plaintext from file:
   char clear_buf[clear_size];
   memset(clear_buf, 0, clear_size );
   if(!clear_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
   ret = fread(clear_buf, 1, clear_size, clear_file);
   if(ret < clear_size ) { cerr << "Error while reading file 1'" << clear_file_name << "'\n"; exit(1); }
   fclose(clear_file);
   
 
   char CDHpublic_buffer [clear_size + client_nounce_size] ;
      
   // Concatenate half key with nonce
   memset(&CDHpublic_buffer, 0, clear_size + client_nounce_size);
   strncpy(CDHpublic_buffer, client_Nonce3, client_nounce_size);
   strncat(CDHpublic_buffer,clear_buf,clear_size);
   memcpy(CDHpublic_buffer, clear_buf, clear_size);
   memcpy(CDHpublic_buffer + clear_size, client_Nonce3, client_nounce_size);
   //CDHpublic_buffer[clear_size+client_nounce_size] = '\0';
   
   //unsigned char* CDHpublic_buffer = new unsigned char[clear_size + client_nounce_size+1];
   long int sizea = clear_size + client_nounce_size;
   CDHpublic_buffer[sizea] = '\0';
   //memcpy(CDHpublic_buffer, CDHpublic_buffer1,(sizea-8));
   //CDHpublic_buffer[sizea];
   //delete[] CDHpublic_buffer1;
  //CDHpublic_buffer1 = CDHpublic_buffer;
   cout << "\n Nonce buffer" << endl;
   BIO_dump_fp(stdout, (unsigned char *)client_Nonce3, client_nounce_size);

   //delete[] client_Nonce3;
  // delete[] client_Nonce1;  // Also, consider why you're deleting this. Was it dynamically allocated outside the function?

   cout << "\n Clearbuf buffer" << endl;
   BIO_dump_fp(stdout, (const char*)clear_buf, clear_size);

   unsigned int c_size = clear_size + client_nounce_size;
   cout << "\n Concatenated buffer" << endl;
   BIO_dump_fp(stdout, (const char *)CDHpublic_buffer, c_size);


   
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
    BIO_dump_fp (stdout, (const char *)sgnt_buf, sizeof(sgnt_buf));
   // delete the digest and the private key from memory:
   EVP_MD_CTX_free(md_ctx);
   EVP_PKEY_free(prvkey);

   // write the signature into a '.sgn' file:
//    string sgnt_file_name = clear_file_name + ".sgn";
//    FILE* sgnt_file = fopen(("storage/keys/"+sgnt_file_name).c_str(), "wb");
//    if(!sgnt_file) { cerr << "Error: cannot open file '" << sgnt_file_name << "' (no permissions?)\n"; exit(1); }
//    ret = fwrite(sgnt_buf, 1, sgnt_size, sgnt_file);
//    if(ret < sgnt_size) { cerr << "Error while writing the file '" << sgnt_file_name << "'\n"; exit(1); }
//    fclose(sgnt_file);
//     BIO_dump_fp (stdout, (const char *)sgnt_buf, sizeof(sgnt_buf));
//   	cout << "File '"<< clear_file_name << "' signed into file '" << sgnt_file_name << "'\n";


    // load cloud certificate:
   string cert_file_name = "Cloud_cert.pem";
   cout << "Cloud Please, type the PEM file containing Client peer's certificate: ";
//    getline(cin, cert_file_name);
//    if(!cin) { cerr << "Error during input\n"; exit(1); }
   FILE* cert_file = fopen(("./Server/publickeys/"+cert_file_name).c_str(), "r");
   if(!cert_file){ cerr << "Error: cannot open file '" << cert_file_name << "' (missing?)\n"; exit(1); }
   X509* cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
   fclose(cert_file);
   if(!cert){ cerr << "Error: PEM_read_X509 returned NULL\n"; exit(1); }

    // Get the size of cert
    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mbio,cert);
   unsigned char* cert_buffer = NULL;
   long cert_size = BIO_get_mem_data(mbio, &cert_buffer);
   uint16_t lmsg = htons(cert_size);

   //  cout<<"\n Cloud Cert is:"<<endl;
   // BIO_dump_fp (stdout, (char* )cert, sizeof(cert));

// Print the certificate details
    BIO* outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
    if(!outbio) { cerr << "Error: Unable to create BIO for stdout\n"; exit(1); }

    X509_print_ex(outbio, cert, XN_FLAG_COMPAT, X509_FLAG_NO_EXTENSIONS);

     X509* cert1;
    BIO* mbio1 = BIO_new(BIO_s_mem());
    BIO_write(mbio1,cert_buffer,cert_size);
    cert1 = PEM_read_bio_X509(mbio1,NULL,NULL,NULL);

   //  cout<<"\n Cloud Cert is 2:"<<endl;
   //  cout << cert1 << endl;


/*


   string cert_file_name = "Cloud_cert.pem";
    cout << "Cloud Please, type the PEM file containing Client peer's certificate: ";
    // getline(cin, cert_file_name);
    // if(!cin) { cerr << "Error during input\n"; exit(1); }
    FILE* cert_file = fopen(("./Server/publickeys/" + cert_file_name).c_str(), "r");
    if(!cert_file) { cerr << "Error: cannot open file '" << cert_file_name << "' (missing?)\n"; exit(1); }
    
    X509* cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if(!cert) { cerr << "Error: PEM_read_X509 returned NULL\n"; exit(1); }

    // Get the size of cert
    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mbio, cert);
    char* cert_buffer = NULL;
    long cert_size = BIO_get_mem_data(mbio, &cert_buffer);
    
    uint16_t lmsg = htons(cert_size);

    cout << "\nCloud Cert is:\n";
    cout << cert_buffer << endl; // PEM is ASCII, so can directly print

    // Clean up resources
    X509_free(cert);
    BIO_free(mbio);

    X509* cert1;
    BIO* mbio1 = BIO_new(BIO_s_mem());
    BIO_write(mbio1,cert_buffer,cert_size);
    cert1 = PEM_read_bio_X509(mbio1,NULL,NULL,NULL);

    cout<<"\n Cloud Cert is 2:"<<endl;
    cout << cert1 << endl;
    
// Clean up resources
    X509_free(cert1);
    BIO_free(mbio1);


*/
   // Cloud Certificate sent to client
    send(sock, (void*)&lmsg, sizeof(uint16_t), 0);
    send(sock, cert_buffer, cert_size, 0);

    //Send the cloud signed diffie hellman public key
	cout<<"\n\n Sending cloud DH keys\n\n";
	//send cloud size of clear buf and signed buf

	cout<<"\n Clear size is:"<<clear_size<<" sgnt size is:"<<sgnt_size<<endl;
	send(sock, &clear_size, sizeof(long int), 0);
	printf("Cloud Clear size to client\n");
	send(sock, &sgnt_size, sizeof(unsigned int), 0);
	printf("Cloud Public key Sent to client\n");


	//send cloud clear buf and signed buf
	send(sock,CDHpublic_buffer, clear_size, 0);
	printf("\nCloud Public key sent to client\n");
   	send(sock,sgnt_buf, sgnt_size, 0);
	printf("Cloud Signed public key sent to client\n");
	
	
	//sending cloud nonce
	send(sock, &cloud_nounce_size, sizeof(long int), 0);
	printf("Cloud nounce size  Sent to cloud\n");
	cout<<"Client side: Client Nounce before sending"<<cloud_nonce<<endl;
	send(sock,cloud_nonce, cloud_nounce_size, 0);
	printf("Cloud nounce sent to client\n");
	
	//sending back client nonce
	//send(sock, (long int*)&c_to_cloud_size, sizeof(long int), 0);
	//printf("Client nounce size  Sent \n");
	//cout<<"Client side: Client Nounce before sending"<<client_nounce<<endl;
	//send(sock,client_nounce, c_to_cloud_size, 0);
	printf("Client nounce sent to cloud back\n");
	



	// read the signed and diffie hellman public key
	cout<<"\n\n\n\nCloud waiting for client signed public keys !!!!!!!!!!\n\n\n";
	
	//reading client size of clear buf and signed buf
	int val1, val2,val3,val4;
	unsigned int client_sgnt_buf_size;
	long int client_clear_buf_size;
	val1 = read(sock, (long int*)&client_clear_buf_size, sizeof(long int));
	val2 = read(sock, (unsigned int*)&client_sgnt_buf_size, sizeof(unsigned int));
	cout<<"\nReceived Client Clear size is:"<<client_clear_buf_size<<" Client Sgnt size is:"<<client_sgnt_buf_size<<endl;

	//reading client clear buf and signed buf
	unsigned char* client_clear_buf = (unsigned char*)malloc(client_clear_buf_size);
	unsigned char* client_sgnt_buf = (unsigned char*)malloc(client_sgnt_buf_size);
   	int valread1 = read(sock, client_clear_buf, client_clear_buf_size);
  	int valread2 = read(sock, client_sgnt_buf, client_sgnt_buf_size);
  	 
  	 // recieving client nounce 
  	 
  	 long int c_to_cloud_size;
	val1 = read(sock, (long int*)&c_to_cloud_size, sizeof(long int));
	unsigned char * client_nounce  = (unsigned char*)malloc(c_to_cloud_size);
  	 int valread3 = read(sock,client_nounce,c_to_cloud_size);
  	 cout<<"\n\nClient nounce received:"<<client_nounce;
  	 //BIO_dump_fp (stdout, (const char *)client_nounce,sizeof(unsigned char));
  	 //cout<<"\n Server Side: Client nounce is:"<<client_nounce<<endl;
  	 
	

	
	
	// recieving cloud nounce 
  	 
  	 long int c_to_client_size1;
	val1 = read(sock, (long int*)&c_to_client_size1, sizeof(long int));
	unsigned char * cloud_nounce1  = (unsigned char*)malloc(c_to_client_size1);
  	 valread3 = read(sock,cloud_nounce1,c_to_client_size1);
  	 cout<<"\n\n\n\nCloud nouce recieved from client back:"<<cloud_nounce1;
  	 cout<<"\nCloud nouce "<<cloud_nonce;
  	 // cout<<sizeof(cloud_nounce1)<<"\n\n\n\nCloud nouce1 \n\n\n";
  	 // cout<<sizeof(cloud_nonce)<<"\n\n\n\nCloud nouce \n\n\n";
  	  int y= sizeof(cloud_nonce);
  	 
  	 if(memcmp(cloud_nonce,cloud_nounce1,sizeof(unsigned char))==0){
	  
	  cout<< "\n cloud nounce is the same\n";
	  //client_nounce++;
	
	  }

          else{
          
           cout<< "\n cloud nounce is not the same\n";
           //exit(1);
           
          }



	 // Save the Client DHkey  file:
	   string sgnt_file_name1 = "ClientDH";
	   FILE* sgnt_file1 = fopen(("storage/Clients_DHkeys/"+sgnt_file_name1).c_str(), "wb");
	   if(!sgnt_file1) { cerr << "Error: cannot open file '" << sgnt_file_name1 << "' (no permissions?)\n"; exit(1); }
	   ret = fwrite(client_clear_buf, 1, client_clear_buf_size, sgnt_file1);
	   if(ret < client_clear_buf_size) { cerr << "Error while writing the file '" << sgnt_file_name1 << "'\n"; exit(1); }
	   fclose(sgnt_file1);
	 //Save the Client signed DHkey  file into a '.sgn' file:
	   string sgnt_file_name2 = "ClientDH.sgn";
	   FILE* sgnt_file2 = fopen(("storage/Clients_DHkeys/"+sgnt_file_name2).c_str(), "wb");
	   if(!sgnt_file2) { cerr << "Error: cannot open file '" << sgnt_file_name2 << "' (no permissions?)\n"; exit(1); }
	   ret = fwrite(client_sgnt_buf, 1, client_sgnt_buf_size, sgnt_file2);
	   if(ret < client_sgnt_buf_size) { cerr << "Error while writing the file '" << sgnt_file_name2 << "'\n"; exit(1); }
	   fclose(sgnt_file2);
	
	
   // deallocate buffers:
   free(client_clear_buf);
   free(client_sgnt_buf);


	//Client Veify signed Public DH key
	//clientverify(buffer1, buffer2);
   return 0;
}


int clientverify(int sock) {
	cout<<"\n\n\n\nClient begining to verify !!!!!!!!!!\n\n\n";
	//printf("%s\n", buffer1);
	//printf("%s\n", buffer2);

	
   int ret; // used for return values


   // load the CA's certificate:
   string cacert_file_name;
   cout << "Client Please, type the PEM file containing CA Public certificate: ";
   getline(cin, cacert_file_name);
   if(!cin) { cerr << "Error during input\n"; exit(1); }
   FILE* cacert_file = fopen(("publickeys/"+cacert_file_name).c_str(), "r");
   if(!cacert_file){ cerr << "Error: cannot open file '" << cacert_file_name << "' (missing?)\n"; exit(1); }
   X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
   fclose(cacert_file);
   if(!cacert){ cerr << "Error: PEM_read_X509 returned NULL\n"; exit(1); }

   // load the CRL:
   string crl_file_name;
   cout << "Client Please, type the PEM file containing the CRL: ";
   getline(cin, crl_file_name);
   if(!cin) { cerr << "Error during input\n"; exit(1); }
   FILE* crl_file = fopen(("publickeys/"+crl_file_name).c_str(), "r");
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
   string cert_file_name;
   cout << "Cloud Please, type the PEM file containing Client peer's certificate: ";
   getline(cin, cert_file_name);
   if(!cin) { cerr << "Error during input\n"; exit(1); }
   FILE* cert_file = fopen(("publickeys/"+cert_file_name).c_str(), "r");
   if(!cert_file){ cerr << "Error: cannot open file '" << cert_file_name << "' (missing?)\n"; exit(1); }
   X509* cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
   fclose(cert_file);
   if(!cert){ cerr << "Error: PEM_read_X509 returned NULL\n"; exit(1); }
   
   // verify the certificate:
   X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
   if(!certvfy_ctx) { cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_STORE_CTX_init(certvfy_ctx, store, cert, NULL);
   if(ret != 1) { cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_verify_cert(certvfy_ctx);
   if(ret != 1) { cerr << "Error: X509_verify_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }

   // print the successful verification to screen:
   char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
   char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
   cout << "Certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully\n";
   free(tmp);
   free(tmp2);
   
   

   // load the signature file:
   string sgnt_file_name;
   cout << "Cloud Please, type the Client signature file: ";
   getline(cin, sgnt_file_name);
   if(!cin) { cerr << "Error during input\n"; exit(1); }
   FILE* sgnt_file = fopen(("storage/Clients_DHkeys/"+sgnt_file_name).c_str(), "rb");
   if(!sgnt_file) { cerr << "Error: cannot open file '" << sgnt_file_name << "' (file does not exist?)\n"; exit(1); }

   // get the file size: 
   // (assuming no failures in fseek() and ftell())
   fseek(sgnt_file, 0, SEEK_END);
   long int sgnt_size = ftell(sgnt_file);
   fseek(sgnt_file, 0, SEEK_SET);

   // read the signature from file:
   unsigned char* sgnt_buf = (unsigned char*)malloc(sgnt_size);
   if(!sgnt_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
   ret = fread(sgnt_buf, 1, sgnt_size, sgnt_file);
   if(ret < sgnt_size) { cerr << "Error while reading file '" << sgnt_file_name << "'\n"; exit(1); }
   fclose(sgnt_file);
    BIO_dump_fp (stdout, (const char *)sgnt_buf, sizeof(sgnt_buf));
   // declare some useful variables:
   const EVP_MD* md = EVP_sha256();
   // read the file to verify from keyboard:
   string clear_file_name;
   cout << "Cloud Please, type the Client file to verify: ";
   getline(cin, clear_file_name);
   if(!cin) { cerr << "Error during input\n"; exit(1); }

   // open the file to verify:
   FILE* clear_file = fopen(("storage/Clients_DHkeys/"+clear_file_name).c_str(), "rb");
   if(!clear_file) { cerr << "Error: cannot open file '" << clear_file_name << "' (file does not exist?)\n"; exit(1); }

   // get the file size: 
   // (assuming no failures in fseek() and ftell())
   fseek(clear_file, 0, SEEK_END);
   long int clear_size = ftell(clear_file);
   fseek(clear_file, 0, SEEK_SET);

   // read the plaintext from file:
   unsigned char* clear_buf = (unsigned char*)malloc(clear_size);
   if(!clear_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
   ret = fread(clear_buf, 1, clear_size, clear_file);
   if(ret < clear_size) { cerr << "Error while reading file '" << clear_file_name << "'\n"; exit(1); }
   fclose(clear_file);
     BIO_dump_fp (stdout, (const char *)clear_buf, sizeof(clear_buf));
   // create the signature context:
   EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
   if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

   // verify the plaintext:
   // (perform a single update on the whole plaintext, 
   // assuming that the plaintext is not huge)
   ret = EVP_VerifyInit(md_ctx, md);
   if(ret == 0){ cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; exit(1); }
   ret = EVP_VerifyUpdate(md_ctx, clear_buf, clear_size);  
   if(ret == 0){ cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n"; exit(1); }
   ret = EVP_VerifyFinal(md_ctx, sgnt_buf, sgnt_size, X509_get_pubkey(cert));
   if(ret == -1){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
      cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
      exit(1);
   }else if(ret == 0){
      cerr << "Error: Invalid signature!\n";
      exit(1);
   }

   // print the successful signature verification to screen:
   cout << "Client, The Signature has been correctly verified! The message is authentic!\n";

   // deallocate data:
   EVP_MD_CTX_free(md_ctx);
   X509_free(cert);
   X509_STORE_free(store);
   //X509_free(cacert); // already deallocated by X509_STORE_free()
   //X509_CRL_free(crl); // already deallocated by X509_STORE_free()
   X509_STORE_CTX_free(certvfy_ctx);
    free(clear_buf);
   free(sgnt_buf);

   return 0;
}


unsigned char authenticate(int sock)
{

//Cloud waiting for client to initiate
cout<<"\n Waiting for Client to initiate Authentication !!!";

long int client_nounce_size, len_user;

//Receiving client's nonce size and username size
read(sock, &client_nounce_size, sizeof(long int));
read(sock, &len_user, sizeof(int));

//Now we receive the Message M1
char client_M1[client_nounce_size+len_user + 1];
read(sock, client_M1, (client_nounce_size+len_user));

char username[len_user];
unsigned char* client_Nonce = new unsigned char[client_nounce_size];
memcpy(client_Nonce, &client_M1, client_nounce_size);
memcpy(username, reinterpret_cast<char*>(&client_M1) + client_nounce_size, len_user);

std::string uname1(username);

cout<<"\n The Username is: "<<uname1<<endl;
cout<<"\n Nonce size"<<client_nounce_size<<endl;
cout<<"\n The Client Nonce is: "<<endl;
BIO_dump_fp(stdout, client_Nonce, client_nounce_size);
//delete[] client_Nonce;
//read(new_socket, (long int*)&client_clear_buf_size, sizeof(long int));
 
//Generating Message M2
cout<<"\n Generating Message M2"<<endl;

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
    

string my_pubkey_file_name = "CDHpublic";
cout << "Please, type the PEM file that will contain cloud DH public key: ";
// getline(cin, my_pubkey_file_name);
// if(!cin) { cerr << "Error during input\n"; exit(1); }
FILE* p1w = fopen(("./Server/storage/keys/"+my_pubkey_file_name).c_str(), "w");
if(!p1w){ cerr << "Error: cannot open file '"<< my_pubkey_file_name << "' (missing?)\n"; exit(1); }
PEM_write_PUBKEY(p1w, my_dhkey);// to seralize and save
fclose(p1w);
string peer_pubkey_file_name;


/*Sign the client public key */
cout<<"\n Signing cloud Diffie-Hellman Key \n";

//Cloud Signing DH public Key
signcloud(sock, client_Nonce, client_nounce_size);
//Cloud Veify client signed Public DH key
clientverify(sock);



cout << "Please, type the PEM file that contains the signed client's DH public key: ";
getline(cin, peer_pubkey_file_name);
if(!cin) { cerr << "Error during input\n"; exit(1); }
/*Load peer public key from a file*/
FILE* p2r = fopen(("storage/Clients_DHkeys/"+peer_pubkey_file_name).c_str(), "r");
if(!p2r){ cerr << "Error: cannot open file '"<< peer_pubkey_file_name <<"' (missing?)\n"; exit(1); }
EVP_PKEY* peer_pubkey = PEM_read_PUBKEY(p2r, NULL, NULL, NULL);//to load
fclose(p2r);
if(!peer_pubkey){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }

printf("Deriving a shared secret\n");// this time we are driving not generating 
/*creating a context, the buffer for the shared key and an int for its length*/
EVP_PKEY_CTX *derive_ctx;
unsigned char *skey;
size_t skeylen;
derive_ctx = EVP_PKEY_CTX_new(my_dhkey,NULL);// in the context new we pass the private my_dhkey generated before then we call the drive_init not the keygen_init
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
	

// Hashing the shared secret to obtain a key Server side.
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







//////////////////////////////////////////////////
//												//
//	DECRYPTION OF RECEIVED PASSWORD	//
//												//
//////////////////////////////////////////////////


//Getting key from digest1 but using IV from digest of encryption

const EVP_CIPHER* cipher = EVP_aes_128_cbc();
int client_iv_len = EVP_CIPHER_iv_length(cipher);
int block_size = EVP_CIPHER_block_size(cipher);





// read the signed and diffie hellman public key
	cout<<"\n\n\n\nCloud reading username and password \n\n\n";
	long int client_cphr_size;
	 //reading client password buffer size
   	int valread5 = read(sock,(long int*)&client_cphr_size, sizeof(long int));
	cout<<"\n Received Cipher size";
	cout<<client_cphr_size;
  	// reading client password buffer
  	unsigned char* client_cphr_buf = (unsigned char*)malloc(client_cphr_size);
  	cout<< "\n one";
  	int valread7 = read(sock, client_cphr_buf, client_cphr_size);
	cout<<"\n received Cipher buf";
	BIO_dump_fp (stdout, (const char *)client_cphr_buf, client_cphr_size);  
	
	//Receive IV
	unsigned char* client_iv = (unsigned char*)malloc(client_iv_len);
	valread7 = read(sock, client_iv, EVP_CIPHER_iv_length(cipher));
	
	//read client uname
	long int client_len_uname1;
	valread7 = read(sock, (long int*)&client_len_uname1, sizeof(long int));
	cout<<"\n Received the length of Uname:"<<client_len_uname1<<endl;
	char* client_uname1 =  (char*) malloc(client_len_uname1);

	valread7 = read(sock,client_uname1, client_len_uname1);
	BIO_dump_fp (stdout, (const char *)client_uname1, client_len_uname1);  
	cout<<"\n before conversion"<<endl;
	
	string uname;
	uname.assign(client_uname1, client_len_uname1);
	
	cout<<"\n Received client username is:"<<uname<<endl; 
	
	 // write the encrypted key, the IV, and the ciphertext into a '.enc' file:
   string cphr_file_name = uname + ".enc";
   FILE* cphr_file = fopen(("storage/users_pass/temp/"+cphr_file_name).c_str(), "wb");
   if(!cphr_file) { cerr << "Error: cannot open file '" << cphr_file_name << "' (no permissions?)\n"; exit(1); }
   
   int ret = fwrite(client_iv, 1, EVP_CIPHER_iv_length(cipher), cphr_file);
   if(ret < EVP_CIPHER_iv_length(cipher)) { cerr << "Error while writing the file '" << cphr_file_name << "'\n"; exit(1); }
   
   ret = fwrite(client_cphr_buf, 1, client_cphr_size, cphr_file);
   if(ret < client_cphr_size) { cerr << "Error while writing the file '" << cphr_file_name << "'\n"; exit(1); }
   
   fclose(cphr_file);

   cout << "Password File '"<< uname << "' encrypted into file '" << cphr_file_name << "'\n";


	//free buffers
	free(client_uname1);
	free(client_cphr_buf);
	free(client_iv);
  
// reading the saved cipher and decrypting

  ret; // used for return values
  int key_len = EVP_CIPHER_key_length(cipher);
   unsigned char *key = (unsigned char*)malloc(key_len);;//(unsigned char *)"0123456789012345";

   memcpy(key, digest, key_len);

   // read the file to decrypt from keyboard:
   string cphr_file_name1 = uname + ".enc";;
   //cout << "Please, type the file to decrypt: ";
   //getline(cin, cphr_file_name);
  // if(!cin) { cerr << "Error during input\n"; exit(1); }

   // open the file to decrypt:
   FILE* cphr_file1 = fopen(("storage/users_pass/temp/"+cphr_file_name1).c_str(), "rb");
   if(!cphr_file1) { cerr << "Error: cannot open file '" << cphr_file_name1 << "' (file does not exist?)\n"; exit(1); }

   // get the file size: 
   // (assuming no failures in fseek() and ftell())
   fseek(cphr_file1, 0, SEEK_END);
   long int cphr_file_size = ftell(cphr_file1);
   fseek(cphr_file1, 0, SEEK_SET);

   // declare some useful variables:
   const EVP_CIPHER* cipher1 = EVP_aes_128_cbc();
   int iv_len = EVP_CIPHER_iv_length(cipher1);
   
   // Allocate buffer for IV, ciphertext, plaintext
   unsigned char* iv = (unsigned char*)malloc(iv_len);
   int cphr_size = cphr_file_size - iv_len;
   unsigned char* cphr_buf = (unsigned char*)malloc(cphr_size);
   unsigned char* clear_buf = (unsigned char*)malloc(cphr_size);
   if(!iv || !cphr_buf || !clear_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }

   // read the IV and the ciphertext from file:
   ret = fread(iv, 1, iv_len, cphr_file);
   if(ret < iv_len) { cerr << "Error while reading file '" << cphr_file_name << "'\n"; exit(1); }
   ret = fread(cphr_buf, 1, cphr_size, cphr_file);
   if(ret < cphr_size) { cerr << "Error while reading file '" << cphr_file_name << "'\n"; exit(1); }
   fclose(cphr_file);

   //Create and initialise the context
   EVP_CIPHER_CTX *ctx;
   ctx = EVP_CIPHER_CTX_new();
   if(!ctx){ cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; exit(1); }
   ret = EVP_DecryptInit(ctx, cipher, key, iv);
   if(ret != 1){
      cerr <<"Error: DecryptInit Failed\n";
      exit(1);
   }
   
   int update_len = 0; // bytes decrypted at each chunk
   int total_len = 0; // total decrypted bytes
   
   // Decrypt Update: one call is enough because our ciphertext is small.
   ret = EVP_DecryptUpdate(ctx, clear_buf, &update_len, cphr_buf, cphr_size);
   if(ret != 1){
      cerr <<"Error: DecryptUpdate Failed\n";
      exit(1);
   }
   total_len += update_len;
   
   //Decrypt Final. Finalize the Decryption and adds the padding
   ret = EVP_DecryptFinal(ctx, clear_buf + total_len, &update_len);
   if(ret != 1){
      cerr <<"Error: DecryptFinal Failed\n";
      exit(1);
   }
   total_len += update_len;
   int clear_size = total_len;

   // delete the context from memory:
   EVP_CIPHER_CTX_free(ctx);
   

   // write the plaintext into a '.dec' file:
   string clear_file_name = cphr_file_name + ".dec.txt";
   FILE* clear_file = fopen(("storage/users_pass/temp/"+clear_file_name).c_str(), "wb");
   if(!clear_file) { cerr << "Error: cannot open file '" << clear_file_name << "' (no permissions?)\n"; exit(1); }
   ret = fwrite(clear_buf, 1, clear_size, clear_file);
   if(ret < clear_size) { cerr << "Error while writing the file '" << clear_file_name << "'\n"; exit(1); }
   fclose(clear_file);
   
   // Just out of curiosity, print on stdout the used IV retrieved from file.
   cout<<"Used IV:"<<endl;
   BIO_dump_fp (stdout, (const char *)iv, iv_len);
   
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
   free(cphr_buf);







//////////////////////////////////////////////////
//												//
//	Comparing Stored hashed password and username for login		//
//												//
//////////////////////////////////////////////////
int ret4; // used for return values  
int ret5; 
//string uname="Alice";
// read the file to encrypt from keyboard:
string clear_file_name4 = uname + ".enc.dec.txt";
string clear_file_name5 = uname + ".enc.dec.txt";
//cout << "Please, type the file to encrypt: ";
//getline(cin, clear_file_name);
//if(!cin) { cerr << "Error during input\n"; exit(1); }
// open the file to encrypt:
FILE* clear_file4 = fopen(("storage/users_pass/temp/"+clear_file_name4).c_str(), "rb");
if(!clear_file4) { cerr << "Error: cannot open file '" << clear_file_name4 << "' (file does not exist?)\n"; exit(1); }

// get the file size: 
// (assuming no failures in fseek() and ftell())
fseek(clear_file4, 0, SEEK_END);
long int clear_size4 = ftell(clear_file4);
fseek(clear_file4, 0, SEEK_SET);
// read the plaintext from file:
unsigned char* clear_buf4 = (unsigned char*)malloc(clear_size4);
if(!clear_buf4) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
ret4 = fread(clear_buf4, 1, clear_size4, clear_file4);
if(ret4 < clear_size4) { cerr << "Error while reading file '" << clear_file_name4 << "'\n"; exit(1); }


// open the file to encrypt:
//string p1 = "./login/";
FILE* clear_file5 = fopen(("storage/users_pass/"+ clear_file_name5).c_str(), "rb");
if(!clear_file5) { cerr << "Error: cannot open file '" << clear_file_name5 << "' (file does not exist?)\n"; exit(1); }

// get the file size: 
// (assuming no failures in fseek() and ftell())
fseek(clear_file5, 0, SEEK_END);
long int clear_size5 = ftell(clear_file5);
fseek(clear_file5, 0, SEEK_SET);
// read the plaintext from file:
unsigned char* clear_buf5 = (unsigned char*)malloc(clear_size5);
if(!clear_buf5) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
ret5 = fread(clear_buf5, 1, clear_size5, clear_file5);
if(ret5 < clear_size5) { cerr << "Error while reading file '" << clear_file_name5 << "'\n"; exit(1); }

if(clear_size4 == clear_size5){cout<<"\n Sizes are equal\n";}else{exit(1);}
int quit = 1;
int v;



}
