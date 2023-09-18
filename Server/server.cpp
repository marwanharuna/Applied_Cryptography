#include "utils/headers.h"
#include "utils/authenticate.h"
#include "utils/login.h"
#include "utils/upload.h"

#define PORT 8080

void freeKey(KEY& sessionkey) {
    delete[] sessionkey.key;
}

using namespace std;

int main(int argc, char const *argv[]) 
{
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    const char *hello = "Hello from server";
    char buffer[1024] = {0};

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return -1;
    }

    // Attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        return -1;
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        return -1;
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        return -1;
    }

    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        perror("accept");
        return -1;
    }

    valread = read(new_socket, buffer, 1024);
    std::cout << buffer << std::endl;
    send(new_socket, hello, strlen(hello), 0);
    std::cout << "Hello message sent" << std::endl;


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
                //Call the authenticate function and return session key and length of key
                sessionkey = authenticate(new_socket);
                username = sessionkey.user;
                first = 1;
            }
            if(counter > maxCounter)
            {
                sessionkey = authenticate(new_socket);
                counter = 0;
            }

            if(login_status ==0)
            {

                size_t counter_server=11;
                unsigned char* clear_buf1;
                size_t clear_size1;

                size_t aad1, aad2, aad3;
                
                Decrypt(new_socket,sessionkey.key,username,&clear_buf1,&clear_size1,&aad1, &aad2, &aad3);



                // Extract and print the data
                printf("Extracted aad1: %zu\n", aad1);
                printf("Extracted aad2: %zu\n", aad2);
                printf("Extracted aad3: %zu\n", aad3);


                // read the file to encrypt from keyboard:
                std::string clear_file_name1 = username + "pass.dec";
                // cout << "Please, type the file to encrypt: ";
                // getline(cin, clear_file_name1);
                // if(!cin) { cerr << "Error during input\n"; exit(1); }

                FILE* clear_file1 = fopen(("./Server/storage/users_pass/"+clear_file_name1).c_str(), "rb");
                if(!clear_file1) { cerr << "Error: cannot open file '" << clear_file_name1 << "' (file does not exist?)\n"; exit(1); }

                // get the file size: 
                // (assuming no failures in fseek() and ftell())
                fseek(clear_file1, 0, SEEK_END);
                long int clear_size2 = ftell(clear_file1);
                fseek(clear_file1, 0, SEEK_SET);

                // read the plaintext from file:
                unsigned char* clear_buf2 = (unsigned char*)malloc(clear_size2);
                if(!clear_buf2) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
                int ret1 = fread(clear_buf2, 1, clear_size2, clear_file1);
                if(ret1 < clear_size2) { cerr << "Error while reading file '" << clear_file_name1 << "'\n"; exit(1); }
                fclose(clear_file1);


                cout<<"clear_buf2:"<<endl;
                BIO_dump_fp (stdout, (const char *)clear_buf2, clear_size2);

                // unsigned char *clear_buf3 = (unsigned char *)"0123456789012345";
                // int clear_size3= 16;


                if (memcmp(clear_buf1, clear_buf2, clear_size1) == 0) 
                {
                        cout << "The original and decrypted values match!" << endl;

                        size_t operation_type= 0;
                        size_t flag1=1;

                        size_t enc_value_len=12;

                        // Allocate memory for iv
                        unsigned char* enc_value = (unsigned char*)malloc(enc_value_len);

                        if (enc_value == NULL) {
                            perror("Memory allocation failed");
                            //return 1;
                        }

                        RAND_poll();
                        // Generate 16 bytes at random. That is my IV
                        int ret = RAND_bytes((unsigned char*)&enc_value[0],enc_value_len);
                        if(ret!=1){
                            cerr <<"Error: RAND_bytes Failed\n";
                            exit(1);
                        } 



                    Encrypt(new_socket,sessionkey.key,username,enc_value,enc_value_len,counter_server,operation_type,flag1);
                    login_status = 1;    
                }
                else{
                    cout<<"\n Login Failed!!!"<<endl;


                        size_t operation_type= 0;
                        size_t flag1=0;

                        size_t enc_value_len=12;

                        // Allocate memory for iv
                        unsigned char* enc_value = (unsigned char*)malloc(enc_value_len);

                        if (enc_value == NULL) {
                            perror("Memory allocation failed");
                            //return 1;
                        }

                        RAND_poll();
                        // Generate 16 bytes at random. That is my IV
                        int ret = RAND_bytes((unsigned char*)&enc_value[0],enc_value_len);
                        if(ret!=1){
                            cerr <<"Error: RAND_bytes Failed\n";
                            exit(1);
                        } 

                     Encrypt(new_socket,sessionkey.key,username,enc_value,enc_value_len,counter_server,operation_type,flag1);
                    login_status = 0;   
                    exit(0); 
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
			//cout<<"\n Input:";
			ssize_t bytesRead = read(new_socket,&opt, sizeof(size_t));
            if (bytesRead == -1) 
            {
                // Handle the read error here
                perror("read");
            } else if (bytesRead == 0) {
                quit = 0;
            }
			if(opt == 1)
			{
				cout<<"\nUpload begin";
				cloud_upload(new_socket, sessionkey.key, username);
				
			}
			else if(opt == 2)
			{	
				cout<<"\nDownload begin";
			}
			else if(opt == 3)
			{
				cout<<"\nSearching all files";

				/*DIR *dr;
				struct dirent *en;
				dr = opendir(("./storage/"+uname+"/").c_str());
				if(dr)
				{
					while((en = readdir(dr)) != NULL)
					{
						cout<<"\n"<<en->d_name;
					}
					closedir(dr);
				}*/
		
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
				}*/

				
			}
			else if(opt == 5)
			{
				cout<<"\nRenaming a file";
				/*
				string oldfile, newfile;
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
			cout<<"1. Yes \n 2. No \n Input:";
            //cout<<"\n Quit: "<<quit<<endl;
            //size_t quit1;
	        read(new_socket, &quit, sizeof(size_t));
            cout<<"\n Quit: "<<quit<<endl;
            if(quit != 1)
            {
                cout<<"\n Session gracefully closed!!!"<<endl;
                freeKey(sessionkey);
               
            };
    }
    // Prompt user to close the connection
    std::cout << "Press any key to close the connection...";
    std::cin.ignore();
    
    // Close the connection
    close(new_socket);

    return 0;
}
