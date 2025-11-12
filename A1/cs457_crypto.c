#include "cs457_crypto.h"

int checkCompleted(char **words){
	int i=0;
	while(words[i]!=NULL){
		printf("%s\n",words[i]);
		if(strchr(words[i],'*')!=NULL){
			return 1;
		}
		i++;
	}
	return 0;
}

int compareWords(char word1[100],char word2[100]){
	int i=0;
	for(i;i<100;i++){
		if(word1[i]!='\0'&&word2[i]=='\n')
			return 0;
		if(word1[i]=='\0'&&word2[i]!='\n')
			return 0;
		if(word1[i]=='\0'&&word2[i]=='\n'){
			return 1;
		}
		if(word1[i]!='*'){
			if(word1[i]!=word2[i]&&word2[i]!='\n')
				return 0;
		}
	}
	return 1;
}

void main(int argc, char** argv){
	int size=1; //opening the file test.txt
	FILE* fptr;
	if(argc==1)
		fptr = fopen("test.txt" , "r");
	else
		fptr = fopen(argv[2] , "r");
	char* fstr = (char*)malloc(sizeof(char));
	char tmp;
	do{ //reading the file and making a string fstr with all the text
		tmp = fgetc(fptr);
		if(tmp==EOF)
			break;
		//printf("%c %d",tmp,size);
		fstr = (char*)realloc(fstr,(++size)*sizeof(char));
		//printf("%d",size);
		fstr[size-2]=tmp;
		fstr[size-1]='\0';
		//printf("%s %d\n",fstr , size);
	}while(1);
	if(!strcmp(argv[1],"1")){
		char *key = generate_key(size);
		printf("Original\n%s\n",fstr);
		fstr = one_time_pad_encr(fstr , size , key);
		printf("\nkey used\n%s\n",key);
		fstr = one_time_pad_decr(fstr , size , key);
		printf("\nAfter one time pad decryption\n%s\n",fstr);
	}
	if(!strcmp(argv[1],"2")){
		printf("Original\n%s\n",fstr);
		fstr=affine_encr(fstr);
		printf("After affine encryption\n%s\n",fstr);
		fstr=affine_decr(fstr);
		printf("After affine decryption\n%s\n",fstr);
	}
	if(!strcmp(argv[1],"3")){
		char str[] = "Pfim im k pwbp pfkp fkm nwwx wxqjedpwt smixc pfw kzzixw krcajipfu kxt civwx km kx kmmicuwxp ix pfw Qaudspwj Mqiwxqw Twdkjpuwxp az pfw Sxivwjmipe az Qjwpw";
		char *words[100]={'\0'};
		char *cipher[100]={'\0'};
		int i=0;
		int word_count=0;
		char *tmp = strtok(str," ");
		while(tmp){
			words[i]=tmp;
			int count = 0;
			cipher[i]=(char*)malloc(100*sizeof(char));
			for(count=0;words[i][count]!='\0';count++){
				cipher[i][count]='*';
			}
			cipher[i][count]='\0';
			i++;
			word_count++;
			printf("%s\n",cipher[i-1]);
			tmp = strtok(NULL," ");
		}
		do{
			for(i=0;i<word_count;i++){
				printf("%s ",words[i]);
			}
			printf("\n");
			for(i=0;i<word_count;i++){
				printf("%s ",cipher[i]);
			}
			printf("\n");
			printf("Enter partially decrpyted word:");
			char input[100];
			scanf("%s",input);
			printf("%s",input);
			FILE* dictionary = fopen("words.txt","r");
			char temp[100];
			while(fgets(temp , sizeof temp , dictionary)!=NULL){
				if(compareWords(input,temp)){
					printf("%s ",temp);
				}
			}
			printf("\n");
			char a, b;
			scanf("%s",input);
			sscanf(input,"%c->%c",&a,&b);
			/*
				TODO make a and b lowercase
			*/
			char* tmp_original = words[0];
			char* tmp_cipher = cipher[0];
			int count=0;
			while(words[count]){
				tmp_original=words[count];
				tmp_cipher=cipher[count];
				i=0;
				for(i=0;tmp_original[i]!='\0';i++){
					char c = tmp_original[i];
					int flag =0;
					if(c<91){
						flag=1;
						c+=32;
					}
					if(c==a){
						tmp_cipher[i]=b-(32*flag);
					}
					
				}
				count++;
			}
			/*
			TODO , READ a and b are the new letters for translating the cipher ,
			check words array for where the letters a are and change the * on cipher with b on those spots 
			*/
			printf("success\n");
		}while(checkCompleted(cipher));
	}
	if(!strcmp(argv[1],"4")){
		char* intermediate = (char*)malloc(strlen(fstr)*sizeof(char));
		char* final = (char*)malloc(strlen(fstr)*sizeof(char));
		int i=0;
		int pos=0;
		for(;fstr[i]!='\0';i++){
			if((fstr[i]>64&&fstr[i]<91)||(fstr[i]>96&&fstr[i]<123)){
				intermediate[pos]=fstr[i];
				pos++;
				final[i]=1;
			}else{
				final[i]=fstr[i];
			}
		}
		intermediate[pos]='\0';
		char* decrypted = (char*)malloc(strlen(intermediate)*sizeof(char));
		printf("original is %s\n",fstr);
		decrypted = trithemius_encr(intermediate);
		printf("Trithemius encrypted is :%s\n",decrypted);
		intermediate = trithemius_decr(decrypted);
		pos=0;
		for(i=0;fstr[i]!='\0';i++){
			if(final[i]==1){
				final[i]=intermediate[pos];
				pos++;
			}
		}
		final[i]='\0';
		printf("Trithemius decrypted is :%s\n",final);
	}
	if(!strcmp(argv[1],"5")){
		int pos = 0; 
		char* intermediate = (char*)malloc(strlen(fstr)*sizeof(char));
		char* final = (char*)malloc(strlen(fstr)*sizeof(char));
		int i=0;
		for(;fstr[i]!='\0';i++){
			if((fstr[i]>64&&fstr[i]<91)||(fstr[i]>96&&fstr[i]<123)){
				intermediate[pos]=fstr[i];
				pos++;
				final[i]=1;
			}else{
				final[i]=fstr[i];
			}
		}
		printf("how many rods:");
		int rods; 
		scanf("%d",&rods);
		final[i]='\0';
		intermediate[pos]='\0';
		intermediate = scytale_encr(intermediate , rods);
		printf("After scytale encryption :%s\n",intermediate);
		intermediate = scytale_decr(intermediate , rods);
		pos=0;
		for(i=0;fstr[i]!='\0';i++){
			if(final[i]==1){
				final[i]=intermediate[pos];
				pos++;
			}
		}
		printf("After scytale decryption :%s\n",intermediate);
	}
	if(!strcmp(argv[1],"6")){
		int pos = 0; 
		char* intermediate = (char*)malloc(strlen(fstr)*sizeof(char));
		char* final = (char*)malloc(strlen(fstr)*sizeof(char));
		int i=0;
		for(;fstr[i]!='\0';i++){
			if((fstr[i]>64&&fstr[i]<91)||(fstr[i]>96&&fstr[i]<123)){
				intermediate[pos]=fstr[i];
				pos++;
				final[i]=1;
			}else{
				final[i]=fstr[i];
			}
		}
		final[i]='\0';
		intermediate[pos]='\0';
		printf("How many rails:");
		int rails;
		scanf("%d",&rails);
		char* encrypted = rail_fence_encr(intermediate , rails);
		printf("After rail encryption %s\n",encrypted);		
		intermediate = rail_fence_decr(encrypted , rails);
		pos=0;
		for(i=0;fstr[i]!='\0';i++){
			if(final[i]==1){
				final[i]=intermediate[pos];
				pos++;
			}
		}
		final[i]='\0';
		printf("After rail decryption %s\n",final);
	}
}

char* rail_fence_decr(char* ciphertext , int rails){
	int size = strlen(ciphertext);
	char matrix[size][rails];
	int i=0;
	int i2=0;
	for(i=0;i<size;i++){
		for(i2=0;i2<rails;i2++){
			matrix[i][i2]=30;
		}
	}
	int direction = 0;
	i=0;
	i2=0;
	for(i=0;i<size;i++){
		matrix[i][i2]=31;
		if(direction==0){
			if(i2==rails-1){
				i2--;
				direction=1;
			}else{
				i2++;
			}
		}else{
			if(i2==0){
				i2++;
				direction=0;
			}else{
				i2--;
			}
		}
	}

	int pos=0;
	i=0;
	i2=0;
	for(i=0;i<rails;i++){
		for(i2=0;i2<size;i2++){
			if(matrix[i2][i]==31){
				matrix[i2][i]=ciphertext[pos];
				
				pos++;
			}
		}
	}
	char *ret =(char*)malloc(size*sizeof(char));
	
	direction = 0;
	i=0;
	i2=0;
	pos=0;
	for(i=0;i<size;i++){
		ret[pos]=matrix[i][i2];
		pos++;
		if(direction==0){
			if(i2==rails-1){
				i2--;
				direction=1;
			}else{
				i2++;
			}
		}else{
			if(i2==0){
				i2++;
				direction=0;
			}else{
				i2--;
			}
		}
	}
	ret[pos]='\0';
	return ret;
}

char* rail_fence_encr(char* plaintext , int rails){
	char matrix[strlen(plaintext)][rails];
	int i=0;
	int i2=0;
	for(i=0;i<strlen(plaintext);i++){
		for(i2=0;i2<rails;i2++){
			matrix[i][i2]='z';
		}
	}
	int direction = 0;
	i=0;
	i2=0;
	for(i=0;i<strlen(plaintext);i++){
		matrix[i][i2]=plaintext[i];
		if(direction==0){
			if(i2==rails-1){
				i2--;
				direction=1;
			}else{
				i2++;
			}
		}else{
			if(i2==0){
				i2++;
				direction=0;
			}else{
				i2--;
			}
		}
	}
	char *out =(char*)malloc(strlen(plaintext)*sizeof(char));
	int pos=0;
	i=0;
	i2=0;

	
	for(i=0;i<rails;i++){
		for(i2=0;i2<strlen(plaintext);i2++){
			if(matrix[i2][i]!='z'){
				out[pos]=matrix[i2][i];
				pos++;
			}
		}
	}
	out[pos]='\0';
	return out;
}

char* scytale_encr(char* plaintext , int diameter){
	int i=0;
	int i2=0;
	int pos=0;
	int limit = ((strlen(plaintext)-1)/diameter)+1;
	char tmp[limit][diameter];
	char c = plaintext[pos];
	while(c!='\0'){
		tmp[i][i2]=c;
		pos++;
		i2++;
		if(i2==diameter){
			i2=0;
			i++;
		}
		c = plaintext[pos];
	}
	pos=0;
	char* out=(char*)malloc(strlen(plaintext)*sizeof(char));
	for(i=0;i<diameter;i++){
		for(i2=0;i2<limit;i2++){
			out[pos]=tmp[i2][i];
			pos++;
		}
	}
	out[pos]='\0';
	return out;
}

char* scytale_decr(char* ciphertext , int diameter){
	int i=0;
	int i2=0;
	int pos=0;
	int limit = ((strlen(ciphertext)-1)/diameter)+1;
	char tmp[limit][diameter];
	char c = ciphertext[pos];
	while(c!='\0'){
		tmp[i2][i]=c;
		pos++;
		i2++;
		if(i2==limit){
			i2=0;
			i++;
		}
		c = ciphertext[pos];
	}	pos=0;
	char* out=(char*)malloc(strlen(ciphertext)*sizeof(char));
	for(i=0;i<limit;i++){
		for(i2=0;i2<diameter;i2++){
			out[pos]=tmp[i][i2];
			pos++;
		}
	}
	out[pos]='\0';
	return out;
}

char* trithemius_encr(char* plaintext){
	int i=0;
	char* out = (char*)malloc(strlen(plaintext)*sizeof(char));
	for(;plaintext[i]!='\0';i++){
		int limit;
		if(plaintext[i]>96)
			limit=122;
		else
			limit=90;
		char c = plaintext[i]+i;
		while(c>limit)
			c = c - 26;
		out[i] = c;
	}
	out[i]='\0';
	return out;
}

char* trithemius_decr(char* ciphertext){
	int i=0;
	char* out = (char*)malloc(strlen(ciphertext)*sizeof(char));
	for(;ciphertext[i]!='\0';i++){
		int limit;
		if(ciphertext[i]>96)
			limit=96;
		else
			limit=64;
		char c = ciphertext[i]-i;
		while(c<limit)
			c = c + 26;
		out[i] = c;
	}
	out[i]='\0';
	return out;
}

char* generate_key(int size){
	//printf("%d\n",size);
	srand(time(NULL));
	char* tmp = (char*)malloc(size*sizeof(char));
	int tmp_size = 1;
	while(tmp_size<size){
		tmp[tmp_size-1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[rand() % 26];
		tmp[tmp_size]= '\0';
		printf("%s %d \n",tmp,tmp_size);
		tmp_size++;
		//printf("%d\n",tmp_size);
	}
	printf("%s\n",tmp);
	return tmp;
}

char* one_time_pad_encr(char* str ,int size , char* key){
		//printf("%s\n",key);
		//printf("%d\n",size);
		char *final = (char*)malloc(size*sizeof(char));
		int i=0;
		for(i=0; i<size-1;i++){
			char temp_char = str[i]^key[i];
			final[i]=temp_char;
		}
		final[size-1]='\0';
		return final;
}

char* one_time_pad_decr(char *decr ,int size, char* key){
	char *final = (char*)malloc(size*sizeof(char));
		for(int i=0; i<size-1;i++){
			char temp_char = decr[i]^key[i];
			final[i]=temp_char;
		}
		final[size-1]='\0';
		return final;
}


char* affine_encr(char* plaintext){
	char* final = (char*)malloc(strlen(plaintext)*sizeof(char));
	int i=0;
	for(i=0;i<strlen(plaintext);i++){
		if(plaintext[i]==' '){
			final[i]=' ';
		}
		else if(plaintext[i]=='\n'){
			final[i]='\n';
		}else{
			if(plaintext[i]>='a'){
				final[i]=((5*(plaintext[i]-'a'))+8)%26+'a';
			}
			else{
				final[i]=(5*(plaintext[i]-'A')+8)%26+'A';
			}
		}
		final[i+1]='\0';
	}
	return final;
}

char* affine_decr(char* ciphertext){
	char* final = (char*)malloc(strlen(ciphertext)*sizeof(char));
	int i=0;
	for(i=0;i<strlen(ciphertext);i++){
		if(ciphertext[i]==' '){
			final[i]=' ';
		}
		else if(ciphertext[i]=='\n'){
			final[i]='\n';
		}else{
			if(ciphertext[i]>='a'){
				int temp=(21*(ciphertext[i]-'a'-8))%26;
				if(temp<0)
					temp = 26+temp;
				final[i]=temp+'a';
				//printf("larger than %d %d %d\n",temp,ciphertext[i], final[i]);
			}
			else{
				int temp=(21*(ciphertext[i]-'A'-8))%26;
				if(temp<0)
					temp = 26+temp;
				final[i]=temp+'A';
			}
		}
		final[i+1]='\0';
	}
	return final;
}