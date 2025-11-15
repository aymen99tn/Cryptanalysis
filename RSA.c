#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <time.h>

const char* p_string="15554903035303856344007671063568213071669822184616101992595534860863803506262760067615727000088295330493705796902296102481798240988227195060316199080930616035532980617309644098719341753037782435645781436420697261984870969742096465765855782491538043554917285285471407866976465359446400695692459955929581561107496250057761324472438514351159746606737260676765872636140119669971105314539393270612398055538928361845237237855336149792618908050931870177925910819318623";

const char* q_string="15239930048457525970295803203207379514343031714151154517998415248470711811442956493342175286216470497855132510489015253513519073889825927436792580707512051299817290925038739023722366499292196400002204764665762114445764643179358348705750427753416977399694184804769596469561594013716952794631383872745339020403548881863215482480719445814165242627056637786302612482697923973303250588684822021988008175106735736411689800380179302347354882715496632291069525885653297";

char* string_to_hex(const char* input_string) {
   if (input_string == NULL) {
      return NULL;
    }
   size_t input_len = strlen(input_string);
   char* hex_output = (char*)malloc(input_len * 2 + 1);
    if (hex_output == NULL) {
        perror("Failed to allocate memory for hex_output");
        return NULL;
    }
    int hex_index = 0;
    for (size_t i = 0; i < input_len; i++) {
        sprintf(&hex_output[hex_index], "%02x", (unsigned char)input_string[i]);
        hex_index += 2;
    }
    hex_output[hex_index] = '\0';

    return hex_output;
}

void key_generation(mpz_t pk[2], mpz_t sk[3]){
   mpz_t p,q,n,phi_n,e,d,gcd;
   mpz_t temp1,temp2;
   gmp_randstate_t state;
   mpz_inits(p,q,n,phi_n,e,d,gcd,temp1,temp2,NULL);
   
   mpz_set_str(p, p_string, 10);
   mpz_set_str(q, q_string, 10);
   mpz_mul(n, p, q);
   mpz_sub_ui(temp1, p, 1);
   mpz_sub_ui(temp2, q, 1);

   mpz_mul(phi_n, temp1, temp2);
   gmp_randinit_default(state);
   do{
      mpz_urandomm(e, state, phi_n);
      mpz_gcd(gcd,e, phi_n);
   }while (mpz_cmp_ui(gcd,1)!=0);
   gmp_randclear(state);
   mpz_invert(d,e,phi_n);
   mpz_set(pk[0], e);
   mpz_set(pk[1], n);
   mpz_set(sk[0], d);
   mpz_set(sk[1], p);
   mpz_set(sk[2], q);
}

void encryption(mpz_t ciphertext, mpz_t* pk,mpz_t plaintext){
   mpz_powm(ciphertext,plaintext,pk[0],pk[1]);
}

void decryption(mpz_t decrypted_msg, mpz_t* sk,mpz_t ciphertext){
   clock_t start, end;
   start = clock();
   mpz_t n;
   mpz_init(n);
   mpz_mul(n,sk[1],sk[2]);
   mpz_powm(decrypted_msg,ciphertext,sk[0],n);
   end = clock();
   double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
   printf("Computation time of the cd mod n decryption is %f \n", time_taken);
   mpz_clear(n);
}

void CRT_decryption(mpz_t decrypted_msg, mpz_t* sk,mpz_t ciphertext){
   clock_t start, end;
   start = clock();
   mpz_t n,temp,p1,q1,dp,dq,cp,cq,mp,mq;
   mpz_inits(n,temp,p1,q1,dp,dq,cp,cq,mp,mq,NULL);

   mpz_mul(n,sk[1],sk[2]);
   mpz_invert(p1,sk[1],sk[2]);
   mpz_invert(q1,sk[2],sk[1]);
   mpz_mod(dp,sk[0],sk[1]-1);
   mpz_mod(dq,sk[0],sk[2]-1);
   mpz_mod(cp,ciphertext,sk[1]);
   mpz_mod(cq,ciphertext,sk[2]);
   mpz_powm(mp,cp,dp,sk[1]);
   mpz_powm(mq,cq,dq,sk[2]);
   mpz_mul(temp,sk[2],q1);
   mpz_mul(decrypted_msg,sk[1],p1);
   mpz_mul(decrypted_msg,decrypted_msg,mq);
   mpz_addmul(decrypted_msg,temp,mp);
   mpz_mod(decrypted_msg,decrypted_msg,n);
   end = clock();
   double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
   printf("Computation time of the CRT-based RSA decryption is= %f \n", time_taken);
   mpz_clears(n,temp,p1,q1,dp,dq,cp,cq,mp,mq,NULL);

}

int main() {
   char input[1024];
   mpz_t pk[2], sk[3], plaintext, ciphertext, decrypted_msg1, decrypted_msg2;
   mpz_inits(plaintext, ciphertext, decrypted_msg1, decrypted_msg2, NULL);
   for (int i = 0; i < 2; i++) {
       mpz_init(pk[i]);
   }
   for (int i = 0; i < 3; i++) {
         mpz_init(sk[i]);
   }
   printf("Enter plaintext message:\n");
   scanf("%s", input);
   printf("Chosen message is m: %s \n \n ", input);
   char* hex_input= string_to_hex(input);
   key_generation(pk, sk);
   gmp_printf("Chosen exponent is e: %Zd \n \n ", pk[0]);
   mpz_set_str(plaintext, string_to_hex(input), 16);

   encryption(ciphertext, pk, plaintext);
   gmp_printf("Ciphertext is c: %Zd \n \n", ciphertext);

   decryption(decrypted_msg1, sk, ciphertext);
   gmp_printf("Decrypted message using the cd mod n decryption is m= %Zd \n \n", decrypted_msg1);
   CRT_decryption(decrypted_msg2, sk, ciphertext);
   gmp_printf("Decrypted message using the CRT decryption m= %Zd \n \n", decrypted_msg2);
   
   return 0;
   }