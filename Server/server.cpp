#include "utils/headers.h"
#include "utils/authenticate.h"
#include "utils/login.h"
#include "utils/upload.h"
#include "utils/download.h"

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
    size_t counter = 0;
    size_t maxCounter = 3;
    while(quit == 1)
    {

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
                // std::cout << "Please, type the file to encrypt: ";
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


                std::cout<<"clear_buf2:"<<endl;
                BIO_dump_fp (stdout, (const char *)clear_buf2, clear_size2);

                // unsigned char *clear_buf3 = (unsigned char *)"0123456789012345";
                // int clear_size3= 16;


                if (memcmp(clear_buf1, clear_buf2, clear_size1) == 0) 
                {
                        std::cout << "The original and decrypted values match!" << endl;

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
                    std::cout<<"\n Login Failed!!!"<<endl;


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

system("clear");
            std::cout<<"\nLogin successfull!!!!";

			size_t opt;
			std::cout<<"\n Welcoome To Your Dashboard "<<username;
			std::cout<<"\n\n\n";
			std::cout<<"\n Select The Operation To Perform\n";
			std::cout<<"\n 1. Upload A File";
			std::cout<<"\n 2. Download A File";
			std::cout<<"\n 3. Search All Files";
			std::cout<<"\n 4. Delete A File";
			std::cout<<"\n 5. Rename A File";
            std::cout<<"\n 6. Logout"<<endl;
			//std::cout<<"\n Input:";

             unsigned char* clear_buf1_m3;
           

            size_t aad1_m3, aad2_m3, aad3_m3, clear_size1_m3;

            Decrypt(new_socket,sessionkey.key,username,&clear_buf1_m3,&clear_size1_m3,&aad1_m3, &aad2_m3, &aad3_m3);


            opt=aad3_m3;


			// ssize_t bytesRead = read(new_socket,&opt, sizeof(size_t));
            // if (bytesRead == -1) 
            // {
            //     // Handle the read error here
            //     perror("read");
            // } else if (bytesRead == 0) {
            //     quit = 0;
            // }
			if(opt == 1)
			{
				std::cout<<"\nUpload begin";
				cloud_upload(new_socket, sessionkey.key, username);
				counter++;
			}
			else if(opt == 2)
			{	
				std::cout<<"\nDownload begin";

                size_t status;

                   unsigned char* clear_buf1_m6;
                    size_t clear_size1_m6;

                    size_t aad1_m6, aad2_m6, aad3_m6;

                    Decrypt(new_socket,sessionkey.key,username,&clear_buf1_m6,&clear_size1_m6,&aad1_m6, &aad2_m6, &aad3_m6);


                    // BIO_dump_fp (stdout, (const char *)clear_buf1_m6, clear_size1_m6);

                    std::string file2(reinterpret_cast<char*>(clear_buf1_m6), clear_size1_m6);
                    std::cout<<"\n File name after decrypting and casting to string: "<<file2<<endl;

                    client_download(new_socket, sessionkey.key, username, file2);
                    counter++;
			}
			else if(opt == 3)
			{
				std::cout<<"\nSearching all files";
                DIR *dr;
				struct dirent *en;
				dr = opendir(("./Server/storage/"+username+"/").c_str());
				string file_list1;
				string file_list;
				string file_list2;
				int count;
				int i=0;
				
				if(dr)
				{
				
			
					while((en = readdir(dr)) != NULL)
					{
						std::cout<<"\n"<<en->d_name;
						file_list = en->d_name;
						file_list2.append(file_list).append("\n");
						
						
						
					}
					std::cout<<file_list2<<endl;
					closedir(dr);
					
					
				}
		
                                  
                    size_t file_len = file_list2.length();
                    char* file = (char*)malloc(file_len);
                    strcpy(file, file_list2.c_str());

                    size_t clear_size_m4 = file_len;
                   

                    // read the plaintext from file:
                    unsigned char* clear_buf_m4 = (unsigned char*)malloc(clear_size_m4);
                    if(!clear_buf_m4) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
                    memcpy(clear_buf_m4, file, clear_size_m4);

                    size_t file_size_client=100;
                    size_t counter_client= 0;
                    size_t operation_type_client=0;

                    Encrypt(new_socket,sessionkey.key,username,clear_buf_m4,clear_size_m4,counter_client,operation_type_client,file_size_client);

                    free(clear_buf_m4);
                    counter++;
			}
			else if(opt == 4)
			{
				std::cout<<"\nDelete a files";
					size_t status;

                   unsigned char* clear_buf1_m6;
                    size_t clear_size1_m6;

                    size_t aad1_m6, aad2_m6, aad3_m6;

                    Decrypt(new_socket,sessionkey.key,username,&clear_buf1_m6,&clear_size1_m6,&aad1_m6, &aad2_m6, &aad3_m6);


                    // BIO_dump_fp (stdout, (const char *)clear_buf1_m6, clear_size1_m6);

                    std::string file2(reinterpret_cast<char*>(clear_buf1_m6), clear_size1_m6);
                    std::cout<<"\n File name after decrypting and casting to string: "<<file2<<endl;

                    status = remove(("./Server/storage/"+username+"/"+file2).c_str());

                    	if(status == 0)
                        {

                            size_t operation_type= 0;

                            size_t del_value_len=12;
                            size_t counter_server1=1;
                            // Allocate memory for iv
                            unsigned char* del_value = (unsigned char*)malloc(del_value_len);

                            if (del_value == NULL) {
                                perror("Memory allocation failed");
                                //return 1;
                            }

                            RAND_poll();
                            // Generate 16 bytes at random. That is my IV
                            int ret = RAND_bytes((unsigned char*)&del_value[0],del_value_len);
                            if(ret!=1){
                                cerr <<"Error: RAND_bytes Failed\n";
                                exit(1);
                              } 



                            Encrypt(new_socket,sessionkey.key,username,del_value,del_value_len,counter_server1,operation_type,status);

                            std::cout<<"\n File deleted Successfully!";
                            free(del_value);
                        }
                        else
                        {
                            std::cout<<"\n Error Deleting File!";


                            size_t operation_type= 0;

                            size_t del_value_len=12;
                             size_t counter_server1=1;
                            // Allocate memory for iv
                            unsigned char* del_value = (unsigned char*)malloc(del_value_len);

                            if (del_value == NULL) {
                                perror("Memory allocation failed");
                                //return 1;
                            }

                            RAND_poll();
                            // Generate 16 bytes at random. That is my IV
                            int ret = RAND_bytes((unsigned char*)&del_value[0],del_value_len);
                            if(ret!=1){
                                cerr <<"Error: RAND_bytes Failed\n";
                                exit(1);
                            } 



                            Encrypt(new_socket,sessionkey.key,username,del_value,del_value_len,counter_server1,operation_type,status);
                            free(del_value);
                        }

				counter++;
			}
			else if(opt == 5)
			{
				std::cout<<"\nRenaming a file";
					size_t status;

                   unsigned char* clear_buf1_m7;
                    size_t clear_size1_m7;

                    size_t aad1_m7, aad2_m7, aad3_m7;

                    Decrypt(new_socket,sessionkey.key,username,&clear_buf1_m7,&clear_size1_m7,&aad1_m7, &aad2_m7, &aad3_m7);



                    std::string file4(reinterpret_cast<char*>(clear_buf1_m7), clear_size1_m7);
                    std::cout<<"\n File name after decrypting and casting to string: "<<file4<<endl;


                    unsigned char* clear_buf1_m8;
                    size_t clear_size1_m8;

                    size_t aad1_m8, aad2_m8, aad3_m8;

                    Decrypt(new_socket,sessionkey.key,username,&clear_buf1_m8,&clear_size1_m8,&aad1_m8, &aad2_m8, &aad3_m8);


                    // BIO_dump_fp (stdout, (const char *)clear_buf1_m6, clear_size1_m6);

                    std::string file5(reinterpret_cast<char*>(clear_buf1_m8), clear_size1_m8);
                    std::cout<<"\n File name after decrypting and casting to string: "<<file5<<endl;

                     if(rename(("./Server/storage/"+username+"/"+file4).c_str(),("./Server/storage/"+username+"/"+file5).c_str()) != 0)
                     {
                            perror("Error renaming file");

                            size_t re_status=0;

                            size_t operation_type= 0;

                            size_t ren_value_len=12;
                            size_t counter_server1=1;
                            // Allocate memory for iv
                            unsigned char* ren_value = (unsigned char*)malloc(ren_value_len);

                            if (ren_value == NULL) {
                                perror("Memory allocation failed");
                                //return 1;
                            }

                            RAND_poll();
                            // Generate 16 bytes at random. That is my IV
                            int ret = RAND_bytes((unsigned char*)&ren_value[0],ren_value_len);
                            if(ret!=1){
                                cerr <<"Error: RAND_bytes Failed\n";
                                exit(1);
                              } 



                            Encrypt(new_socket,sessionkey.key,username,ren_value,ren_value_len,counter_server1,operation_type,re_status);

                            std::cout<<"\n File renamed Successfully!";
                            free(ren_value);



                     }
                   
                    else
                    {
                        std::cout<<"File renamed successfully";

                            size_t re_status=1;

                            size_t operation_type= 0;

                            size_t ren_value_len=12;
                            size_t counter_server1=1;
                            // Allocate memory for iv
                            unsigned char* ren_value = (unsigned char*)malloc(ren_value_len);

                            if (ren_value == NULL) {
                                perror("Memory allocation failed");
                                //return 1;
                            }

                            RAND_poll();
                            // Generate 16 bytes at random. That is my IV
                            int ret = RAND_bytes((unsigned char*)&ren_value[0],ren_value_len);
                            if(ret!=1){
                                cerr <<"Error: RAND_bytes Failed\n";
                                exit(1);
                              } 



                            Encrypt(new_socket,sessionkey.key,username,ren_value,ren_value_len,counter_server1,operation_type,re_status);

                            std::cout<<"\n File renamed Successfully!";
                            free(ren_value);
                    }
                   

                counter++;
			}
            else if(opt == 6)
                     {
                        std::cout<<"\n Logging out in progress..."<<endl;
                        quit = 0;
                        freeKey(sessionkey);
                        close(new_socket);
                        exit(1);
                     }
			else
			{
				std::cout<<"Wrong Option Selected";
			}


			std::cout<<"\n\t Do Want To Perform Another Operation!!!";
			std::cout<<"1. Yes \n 2. No \n Input:";
            //std::cout<<"\n Quit: "<<quit<<endl;
            //size_t quit1;
	        read(new_socket, &quit, sizeof(size_t));
            std::cout<<"\n Quit: "<<quit<<endl;
            if(quit != 1)
            {
                std::cout<<"\n Session gracefully closed!!!"<<endl;
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
