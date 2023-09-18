#include "utils/headers.h"
#include "utils/authenticate.h"
#include "utils/login.h"
#include "utils/upload.h"

#define PORT 8080

void freeKey(KEY& sessionkey) {
    delete[] sessionkey.key;
}

using namespace std;

int main(int argc, char const *argv[]) {
    
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    const char *hello = "Hello from client";
    char buffer[1024] = {0};

    // Socket creation
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cout << "Socket creation error" << std::endl;
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        std::cout << "Invalid address/Address not supported" << std::endl;
        return -1;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cout << "Connection failed" << std::endl;
        return -1;
    }

    // Send a message to the server
    send(sock, hello, strlen(hello), 0);
    std::cout << "Hello message sent" << std::endl;

    // Receive a response from the server
    valread = read(sock, buffer, 1024);
    std::cout << buffer << std::endl;
    
    size_t quit = 1;
    int first = 0;
    int login_status = 0;
    while(quit == 1)
    {

        int counter = 0;
        int maxCounter = 10;
         //declare the struct for session key
        KEY sessionkey;

        
        static std::string username;
        

       if(first == 0)
        {

        std::cout<< "\nEnter Your Username: ";
        getline(std::cin, username);
        //Call the authenticate function and return session key and length of key
        sessionkey = authenticate(sock, username);

        first = 1;
        }
        //   printf("\n Client Main Here it is the shared secret: \n");
        // BIO_dump_fp (stdout, (const char *)sessionkey.key, sessionkey.key_len);

        if(counter > maxCounter)
        {
          sessionkey = authenticate(sock, username);
          counter = 0;
        }

        if(login_status ==0)
        {
          std::string passwd;
          cout << "\nEnter Your Password: ";
          getline(cin, passwd);

          string clearpass;
          clearpass = username+passwd;
          int clearpass_len = clearpass.length();

          char* hashpass;
          //allocate memory for digest
          //if(hashpass < 0){exit(1);}
          //else{
          //hashpass = (char*) malloc(clearpass_len+1);
          //}
          hashpass = (char*) malloc(clearpass_len);
          strcpy(hashpass, clearpass.c_str());

          // Hashing the shared secret to obtain a key. and to increase the entropy of the shared secret key
          //create digest pointer and length variable
          unsigned char* pwd_digest;
          unsigned int pwd_digestlen;	
          // Create and init context
          EVP_MD_CTX *Hctx2;
          Hctx2 = EVP_MD_CTX_new();
            cout<<"\n-2";
          //allocate memory for digest and this time we know how big the buffer is because it is output of hash function so 256 bit which is fixed
          pwd_digest = (unsigned char*) malloc(EVP_MD_size(EVP_sha256()));	
          //init, Update (only once) and finalize digest
          EVP_DigestInit(Hctx2, EVP_sha256());// declare hash funciton we want to use 

          EVP_DigestUpdate(Hctx2, (unsigned char*)hashpass, clearpass_len);// we send the input of the hash funciton 

          EVP_DigestFinal(Hctx2, pwd_digest, &pwd_digestlen); //the digest final will retrive the hash output and put in the declaed buffer digest

          //REMEMBER TO FREE CONTEXT!!!!!!
          EVP_MD_CTX_free(Hctx2);
          free(hashpass);
          //Print digest to screen in hexadecimal
          // cout<<"\n-3";
          // int n2;

          // printf("Hashed password Digest is:\n");
          // for(n2=0;pwd_digest[n2]!= '\0'; n2++)
          //   printf("%02x", (unsigned char) pwd_digest[n2]);
          // printf("\n");

          // Specify the file path where you want to save the digest
    // const char* file_path = "./Client/x.dec";

    // // Create and open a binary file for writing
    // ofstream outfile(file_path, ios::binary);
    
    // if (!outfile) {
    //     cerr << "Error opening file for writing." << endl;
    //     return 1;
    // }

    // // Write the pwd_digest to the file
    // outfile.write(reinterpret_cast<const char*>(pwd_digest), pwd_digestlen);
    
    // if (!outfile) {
    //     cerr << "Error writing to file." << endl;
    //     return 1;
    // }

    // // Close the file
    // outfile.close();

    // cout << "pwd_digest has been written to " << file_path << endl;

          size_t file_size_client=100;
          size_t counter_client= 0;
          size_t operation_type_client=0;
          Encrypt(sock,sessionkey.key,username,pwd_digest,pwd_digestlen,file_size_client,counter_client,operation_type_client);
          free(pwd_digest);
            //waiting for server to confirm username and password
            cout<<"\n Waiting for Server to confirm Username And Password!!!!\n";

            unsigned char* clear_buf1;
              //int clear_size1;

              size_t aad1, aad2, aad3, clear_size1;
            
            Decrypt(sock,sessionkey.key,username,&clear_buf1, &clear_size1,&aad1, &aad2, &aad3);

              size_t flag1=aad3; 



            if(flag1 == 0)
            {
              cout<<"\n Username and Password is not Correct!!!\n";
              exit(1);
            }
            else if(flag1 == 1)
            {
              cout<<"\n Username and Password is Correct!!!\n";
              login_status = 1;
            }

        }

        cout<<"\nLogin successfull!!!!";

			size_t opt;
			cout<<"\n Welcoome To Your Dashboard "<<username;
			cout<<"\n\n\n";
			cout<<"\n Select The Operation To Perform\n";
			cout<<"\n 1. Upload A File";
			cout<<"\n 2. Download A File";
			cout<<"\n 3. Search All Files";
			cout<<"\n 4. Delete A File";
			cout<<"\n 5. Rename A File";
			cout<<"\n Input:";
			cin>>opt;
			send(sock,&opt, sizeof(size_t), 0);
			if(opt == 1)
			{
				cout<<"\nUpload begin";
				cout<<"key before calling client upload():"<<endl;
        client_upload(sock, sessionkey.key, username);

				
			}
			else if(opt == 2)
			{	
				cout<<"\nDownload begin";
				// string file_name;
				// cout<<"\n Enter The File to Download:";
				// cin>>file_name;
				// int file_len = file_name.length();
				// char* file = (char*)malloc(file_len);
				// strcpy(file, file_name.c_str());
			}
			else if(opt == 3)
			{
				cout<<"\nSearching all files";

				// DIR *dr;
				// struct dirent *en;
				// dr = opendir(("./storage/"+uname+"/").c_str());
				// if(dr)
				// {
				// 	while((en = readdir(dr)) != NULL)
				// 	{
				// 		cout<<"\n"<<en->d_name;
				// 	}
				// 	closedir(dr);
				// }
		
			}
			else if(opt == 4)
			{
				cout<<"\nDelete a files";
				/*int status;
				string file_to_delete;
				cout<<"\n Enter The file to delete:";
				cin>>file_to_delete;
				status = remove(("./storage/"+uname+"/"+file_to_delete).c_str());
				if(status == 0)
				{
					cout<<"\n File deleted Successfully!";
				}
				else
				{
					cout<<"\n Error Deleting File!";
				}
*/
				
			}
			else if(opt == 5)
			{
				cout<<"\nRenaming a file";

				/*string oldfile, newfile;
				cout<<"\n Enter file to rename:";
				cin>>oldfile;
				cout<<"\n Enter new name:";
				cin>>newfile;
				if(rename(("./storage/"+uname+"/"+oldfile).c_str(),("./storage/"+uname+"/"+newfile).c_str()) != 0)
				perror("Error renaming file");
				else
				cout<<"File renamed successfully";*/
			}
			else
			{
				cout<<"Wrong Option Selected";
			}


			cout<<"\n\t Do Want To Perform Another Operation!!!";
			cout<<"\n1. Yes \n 2. No \n Input:";
			cin>>quit;
      cout<<"\n Quit: "<<quit<<endl;
			send(sock, &quit, sizeof(size_t), 0);
        if(quit != 1)
          {
            cout<<"\n Session gracefully closed!!!"<<endl;
            freeKey(sessionkey);
          }
        
      }
     

    // Prompt user to close the connection
    std::cout << "Press any key to close the connection...";
    std::cin.ignore();

    // Close the connection
    close(sock);

    return 0;
}
