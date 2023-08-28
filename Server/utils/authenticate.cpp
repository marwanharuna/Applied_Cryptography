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

//Signing begins here from Authenticate()
int signcloud(size_t sock, unsigned char* client_Nonce, size_t client_nonce_size) {

cout<<"\n\n\n\nCloud begining to sign !!!!!!!!!!\n\n\n";
   size_t ret; // used for return values

	//Generate new client nonce

	cout<<"Creating new cloud nonce . . ."<<endl;
	RAND_poll();

	const size_t nonce_len = 16;
	//unsigned char client_nounce[16];
	unsigned char* cloud_nonce = nullptr;
    try {
        cloud_nonce = new unsigned char[nonce_len];
    } catch (std::bad_alloc& e) {
        std::cerr << "Memory allocation failed: " << e.what() << std::endl;
        return 1; // Indicate failure to the caller
    }
	size_t rc = RAND_bytes(cloud_nonce, nonce_len);
	size_t cloud_nounce_size= sizeof(cloud_nonce);
	if (rc != 1) {
    size_t err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    fprintf(stderr, "Random number generation error: %s\n", err_buf);
    exit(1);
    }

   
 

    cout<<"\n Client nonce in sign:"<<client_Nonce<<endl;
   //BIO_dump_fp (stdout, (unsigned char *)client_Nonce, client_nonce_size);

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
   size_t clear_size = ftell(clear_file);
   fseek(clear_file, 0, SEEK_SET);

   // read the plaintext from file:
   unsigned char* clear_buf = nullptr;
   try {
        clear_buf = new unsigned char[clear_size];
    } catch (std::bad_alloc& e) {
        std::cerr << "Memory allocation failed: " << e.what() << std::endl;
        return 1; // Indicate failure to the caller
    }
   ret = fread(clear_buf, 1, clear_size, clear_file);
   if(ret < clear_size ) { cerr << "Error while reading file 1'" << clear_file_name << "'\n"; exit(1); }
   fclose(clear_file);

    
  
   unsigned char* CDHpublic_buffer = nullptr;
     size_t c_size = clear_size + client_nonce_size ; 
   try {
        CDHpublic_buffer = new unsigned char[c_size];
    } catch (std::bad_alloc& e) {
        std::cerr << "Memory allocation failed: " << e.what() << std::endl;
        return 1; // Indicate failure to the caller
    }

   // Concatenate half key with nonce
  // memset(&CDHpublic_buffer, 0, (clear_size + client_nonce_size));
    cout<<"\n Here 1"<<endl;
  
   // strncpy(CDHpublic_buffer, client_Nonce, client_nonce_size);
   // strncat(CDHpublic_buffer,clear_buf,clear_size);
   memcpy(CDHpublic_buffer, clear_buf, clear_size);
   memcpy(CDHpublic_buffer + clear_size, client_Nonce, client_nonce_size);

    cout<<"\n Size of nonce: "<<client_nonce_size<<endl;
    cout << "\n Nonce buffer" << endl;
   //printHexWithAscii(client_Nonce, client_nonce_size);
   //BIO_dump_fp(stdout, client_Nonce, client_nonce_size);
    //free client nonce
    delete[] client_Nonce;

  
 

//    cout<<"\n Clear_buf size: "<<clear_size<<endl;
//    cout << "\n Clearbuf buffer" << endl;
   //printHexWithAscii(clear_buf, clear_size);
   //BIO_dump_fp(stdout, (const char*)clear_buf, clear_size);

    
    


//    cout<<"\n concatenated buf size: "<<c_size<<endl;
//    cout << "\n Concatenated buffer" << endl;
   //printHexWithAscii(CDHpublic_buffer, c_size);
   //BIO_dump_fp(stdout, (unsigned char *)CDHpublic_buffer, c_size);
    


    cout<<"\n Concatenated buf size: "<<c_size<<endl;
    cout << "\n original Concatenated buf" << endl;
    //printHexWithAscii(CDHpublic_buffer, c_size);
    BIO_dump_fp(stdout, CDHpublic_buffer, c_size);


   // declare some useful variables:
   const EVP_MD* md = EVP_sha256();

   // create the signature context:
   EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
   if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

   // allocate buffer for signature:
   unsigned char* sgnt_buf = nullptr;
   try {
        sgnt_buf = new unsigned char[EVP_PKEY_size(prvkey)];
    } catch (std::bad_alloc& e) {
        std::cerr << "Memory allocation failed: " << e.what() << std::endl;
        return 1; // Indicate failure to the caller
    }

   // sign the plaintext:
   // (perform a single update on the whole plaintext, 
   // assuming that the plaintext is not huge)

    
    
  
   ret = EVP_SignInit(md_ctx, md);
   if(ret == 0){ cerr << "Error: EVP_SignInit returned " << ret << "\n"; exit(1); }
   ret = EVP_SignUpdate(md_ctx, CDHpublic_buffer, c_size);
   if(ret == 0){ cerr << "Error: EVP_SignUpdate returned " << ret << "\n"; exit(1); }
   unsigned int sgnt_size;
   ret = EVP_SignFinal(md_ctx, sgnt_buf, &sgnt_size, prvkey);
   if(ret == 0){ cerr << "Error: EVP_SignFinal returned " << ret << "\n"; exit(1); }
    //BIO_dump_fp (stdout, (const char *)sgnt_buf, sizeof(sgnt_buf));
   // delete the digest and the private key from memory:
   EVP_MD_CTX_free(md_ctx);
   EVP_PKEY_free(prvkey);
    delete[] CDHpublic_buffer;

 

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
/*
    // Get the size of cert
    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mbio,cert);
   unsigned char* cert_buffer = NULL;
   size_t cert_size = BIO_get_mem_data(mbio, &cert_buffer);
   uint16_t lmsg = htons(cert_size);

    cout<<"\n Cloud Cert is:"<<endl;
    //cert_buffer[cert_size] = '\0';
    BIO_dump_fp (stdout, cert_buffer, cert_size);



// Print the certificate details
    BIO* outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
    if(!outbio) { cerr << "Error: Unable to create BIO for stdout\n"; exit(1); }

    

     X509* cert1;
    BIO* mbio1 = BIO_new(BIO_s_mem());
    BIO_write(mbio1,cert_buffer,cert_size);
    cert1 = PEM_read_bio_X509(mbio1,NULL,NULL,NULL);
    X509_print_ex(outbio, cert1, XN_FLAG_COMPAT, X509_FLAG_NO_EXTENSIONS);

    //free buffers

    BIO_free(outbio);
    X509_free(cert1);
    BIO_free(mbio1);
    X509_free(cert);
    BIO_free(mbio);
*/

    // Get the size of cert
    BIO* mbio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mbio, cert);

    // Determine the size of the data in the BIO
    size_t cert_size = BIO_pending(mbio);

    // Allocate memory for the certificate buffer
    unsigned char* cert_buffer = new unsigned char[cert_size];

    // Read the data from the BIO into the buffer
    BIO_read(mbio, cert_buffer, cert_size);
   


   // Cloud Certificate sent to client
    ret = send(sock, &cert_size, sizeof(size_t), 0);
    if(ret == -1)
    {
        handleErrors("Cloud Cert Size");
    }
    cout<<"\n Cloud cert size: "<<cert_size<<endl;
    ret = send(sock, cert_buffer, cert_size, 0);
    if(ret == -1)
    {
        handleErrors("Cloud Cert");
    }

	
    //send cloud size of clear buf and signed buf
	cout<<"\n Clear size is:"<<clear_size<<" sgnt size is:"<<sgnt_size<<endl;
	ret = send(sock, &clear_size, sizeof(size_t), 0);
    if(ret == -1)
    {
        handleErrors("Cloud Clear_buf Size");
    }
	printf("Cloud Clear size to client\n");
	ret = send(sock, &sgnt_size, sizeof(unsigned int), 0);
    if(ret == -1)
    {
        handleErrors("Cloud Clear Size");
    }
	


//    cout<<"\n Clear buf size: "<<(c_size)<<endl;
//     cout << "\n Clear buf" << endl;
//   BIO_dump_fp(stdout, sgnt_buf, sgnt_size);

	//send cloud clear buf and signed buf
	ret = send(sock, clear_buf, clear_size, 0);
    if(ret < clear_size)
    {
        handleErrors("Cloud Clear_bufe");
    }
	printf("\nCloud Public key sent to client\n");
   	ret = send(sock, sgnt_buf, sgnt_size, 0);
    if(ret < sgnt_size)
    {
        handleErrors("Cloud sgnt_buf");
    }
	printf("Cloud Signed public key sent to client\n");
	
	
	//sending cloud nonce
	ret = send(sock, &cloud_nounce_size, sizeof(size_t), 0);
    if(ret == -1)
    {
        handleErrors("Cloud nonce Size");
    }
	printf("Cloud nounce size  Sent to cloud\n");
	cout<<"Client side: Client Nounce before sending"<<cloud_nonce<<endl;
	ret = send(sock,cloud_nonce, cloud_nounce_size, 0);
    if(ret == -1)
    {
        handleErrors("Cloud Nonce");
    }
	printf("Cloud nounce sent to client\n");


    delete[] sgnt_buf;
    delete[] clear_buf;
    delete[] cloud_nonce;
    delete[] cert_buffer;
 /*




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

    */
   return 0;
}

// Authentication begins here from Main()
unsigned char authenticate(int sock)
{

//Cloud waiting for client to initiate
cout<<"\n Waiting for Client to initiate Authentication !!!";

//Declare lengths
size_t client_nonce_size, len_user, Client_M1_size, ret;

//Receiving client's nonce size and username size
ret = read(sock, &client_nonce_size, sizeof(size_t));
if(ret == -1)
    {
        handleErrors("Client Nonce Size");
    }
ret = read(sock, &len_user, sizeof(size_t));
if(ret == -1)
    {
        handleErrors("Client Len Size");
    }
// cout<<"\n Check 1"<<endl;
// cout<<"\ Size of client's nonce: "<<client_nonce_size<<endl;
// cout<<"\n Size of len: "<<len_user<<endl;
Client_M1_size = client_nonce_size + len_user;
// cout<<"\n Size of Client_M1_size: "<<Client_M1_size<<endl;

//Now we receive the Message M1
unsigned char* client_M1 = nullptr;
try {
        client_M1 = new unsigned char[Client_M1_size];
    } catch (std::bad_alloc& e) {
        std::cerr << "Memory allocation failed: " << e.what() << std::endl;
        return 1; // Indicate failure to the caller
    }
ret = read(sock, client_M1, Client_M1_size);
if(ret == -1)
    {
        handleErrors("Client Message M1");
    }
//BIO_dump_fp(stdout, client_M1, Client_M1_size);

//Splitting message M1
char username[len_user];
unsigned char* client_Nonce = nullptr;
try {
        client_Nonce = new unsigned char[client_nonce_size];
    } catch (std::bad_alloc& e) {
        std::cerr << "Memory allocation failed: " << e.what() << std::endl;
        return 1; // Indicate failure to the caller
    }
memcpy(client_Nonce, client_M1, client_nonce_size);
memcpy(username, client_M1 + client_nonce_size, len_user);
delete[] client_M1;


std::string uname1(username);

cout<<"\n The Username is: "<<uname1<<endl;
cout<<"\n Nonce size"<<client_nonce_size<<endl;
cout<<"\n The Client Nonce is: "<<endl;
//BIO_dump_fp(stdout, client_Nonce, client_nonce_size);
//delete[] client_Nonce;
//read(new_socket, (long int*)&client_clear_buf_size, sizeof(long int));
 
//Generating Message M2
cout<<"\n Generating Message M2"<<endl;

//GENERATING MY EPHEMERAL KEY
// Use built-in parameters 
printf("Start: loading standard DH parameters\n");
EVP_PKEY *params;// structure param// we pass empty params
if(NULL == (params = EVP_PKEY_new())) handleErrors("Params Initialization failed");
DH* temp = get_dh2048_auto();
if(1 != EVP_PKEY_set1_DH(params,temp)) handleErrors("Temp Initialization failed");// to retrive the parameters inside your code and you use this fucniton to retirve the parameters inside the EVP_PKEY_set1_DH 
  //so pass empty EVP_pkey Param structure and this funciton   copies the values retrived from the command lien tool to the structured param
DH_free(temp);
printf("\n");
printf("Generating ephemeral DH KeyPair\n");
// Create context for the key generation  //ready to generate the DH key pairs
EVP_PKEY_CTX *DHctx;
// initialize the context with params
if(!(DHctx = EVP_PKEY_CTX_new(params, NULL))) handleErrors("DHctx Initialization failed");
// Generate a new key  //not drive a key, so the APi is KEYGEN_INIThj
EVP_PKEY *my_dhkey = NULL;
if(1 != EVP_PKEY_keygen_init(DHctx)) handleErrors("my_dhkey Initialization failed");
if(1 != EVP_PKEY_keygen(DHctx, &my_dhkey)) handleErrors("my_dhkey generation failed");// Generate a key which will be contained in the structure named EVP_PKEY NAMED MY MY_DHKEY  
// now we have in my_dhkey our private key which also contains the public key, with seralization API you will be able to extract from my_dhkey the public key to store inside the PEM FILE
//write my public key into a file, so the other client can read it


  

string my_pubkey_file_name = "CDHpublic";
//cout << "Please, type the PEM file that will contain cloud DH public key: ";
// getline(cin, my_pubkey_file_name);
// if(!cin) { cerr << "Error during input\n"; exit(1); }
FILE* p1w = fopen(("./Server/storage/keys/"+my_pubkey_file_name).c_str(), "w");
if(!p1w){ cerr << "Error: cannot open file '"<< my_pubkey_file_name << "' (missing?)\n"; exit(1); }
PEM_write_PUBKEY(p1w, my_dhkey);// to seralize and save
fclose(p1w);
//string peer_pubkey_file_name;


//Sign the client public key 
cout<<"\n Signing cloud Diffie-Hellman Key \n";

//Cloud Signing DH public Key
signcloud(sock, client_Nonce, client_nonce_size);

cout<<"\n Waiting for Message M3"<<endl;

/*
//Cloud Veify client signed Public DH key
clientverify(sock);



cout << "Please, type the PEM file that contains the signed client's DH public key: ";
getline(cin, peer_pubkey_file_name);
if(!cin) { cerr << "Error during input\n"; exit(1); }
//Load peer public key from a file
FILE* p2r = fopen(("storage/Clients_DHkeys/"+peer_pubkey_file_name).c_str(), "r");
if(!p2r){ cerr << "Error: cannot open file '"<< peer_pubkey_file_name <<"' (missing?)\n"; exit(1); }
EVP_PKEY* peer_pubkey = PEM_read_PUBKEY(p2r, NULL, NULL, NULL);//to load
fclose(p2r);
if(!peer_pubkey){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }

printf("Deriving a shared secret\n");// this time we are driving not generating 
//creating a context, the buffer for the shared key and an int for its length
EVP_PKEY_CTX *derive_ctx;
unsigned char *skey;
size_t skeylen;
derive_ctx = EVP_PKEY_CTX_new(my_dhkey,NULL);// in the context new we pass the private my_dhkey generated before then we call the drive_init not the keygen_init
if (!derive_ctx) handleErrors();
if (EVP_PKEY_derive_init(derive_ctx) <= 0) handleErrors();
//Setting the peer with its pubkey // so we continue to set the public key uploaded in memroy form the file of the peer and you can see peer_pubkey is already structured in EVP_PKEY
if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pubkey) <= 0) handleErrors();
// Determine buffer length, by performing a derivation but writing the result nowhere 
EVP_PKEY_derive(derive_ctx, NULL, &skeylen);//  then we call the drive funciton. so we created and initilaizzed the context and we tell the material to the context the material with which he should work and then we command the context this manager of encryption of cryptographic operation what we want him to do  
//at line 122 we determine the buffer length also cuz the derivation of the DH the shared secret  can have a variable length.so open ssl gives us an option to determine exactly the number of bits to allocate in order to have precise buffer for the long derived shared secret 
//allocate buffer for the shared secret
skey = (unsigned char*)(malloc(int(skeylen)));
if (!skey) handleErrors();
//Perform again the derivation and store it in skey buffer//
if (EVP_PKEY_derive(derive_ctx, skey, &skeylen) <= 0) handleErrors();
printf("Here it is the shared secret: \n");
BIO_dump_fp (stdout, (const char *)skey, skeylen);
//WARNING! YOU SHOULD NOT USE THE DERIVED SECRET AS A SESSION KEY!
 * IS COMMON PRACTICE TO HASH THE DERIVED SHARED SECRET TO OBTAIN A SESSION KEY.
 //

*/

//delete[] client_Nonce;

//FREE EVERYTHING INVOLVED WITH THE EXCHANGE (not the shared secret tho)
//EVP_PKEY_CTX_free(derive_ctx);
//EVP_PKEY_free(peer_pubkey);
EVP_PKEY_free(my_dhkey);
EVP_PKEY_CTX_free(DHctx);
EVP_PKEY_free(params);
return 0;

}