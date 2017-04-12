/*
  A DAA implementation following the scheme presented by Brickell & Li in:
  	  	  	  	  	  	  	  	  "A Pairing-Based DAA scheme Further Reducing TPM  Resources"

   Compile with modules as specified below

   NOW IN USE --->For MR_PAIRING_CP curve
   cl /O2 /GX daa.cpp cp_pair.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_MNT curve
   cl /O2 /GX daa.cpp mnt_pair.cpp zzn6a.cpp ecn3.cpp zzn3.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib
	
   For MR_PAIRING_BN curve
   cl /O2 /GX daa.cpp bn_pair.cpp zzn12a.cpp ecn2.cpp zzn4.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_KSS curve
   cl /O2 /GX daa.cpp kss_pair.cpp zzn18.cpp zzn6.cpp ecn3.cpp zzn3.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   For MR_PAIRING_BLS curve
   cl /O2 /GX daa.cpp bls_pair.cpp zzn24.cpp zzn8.cpp zzn4.cpp zzn2.cpp ecn4.cpp big.cpp zzn.cpp ecn.cpp miracl.lib

   P.S. I don't use a static library miracl.lib, i add into project all the required libraries and compile them together with
   	    others sources.

*/

#include <iostream>
#include <ctime>
#include <iostream>
#include "big.h"
#include "ecn.h"
#include "ecn2.h"

//********* choose just one of these pairs **********
//#define MR_PAIRING_CP      // AES-80 security
//#define AES_SECURITY 80

//#define MR_PAIRING_MNT	// AES-80 security
//#define AES_SECURITY 80

#define MR_PAIRING_BN    // AES-128 or AES-192 security
#define AES_SECURITY 128
//#define AES_SECURITY 192

//#define MR_PAIRING_KSS    // AES-192 security
//#define AES_SECURITY 192

//#define MR_PAIRING_BLS    // AES-256 security
//#define AES_SECURITY 256
//*********************************************

#include "pairing_3.h"
int hash_count  		  = 0;
int mad_count 			  = 0;
int mult_g1_count 		  = 0;
int mult_g2_count 	      = 0;

int mrpadd_count		  = 0;
int mrpsub_count		  = 0;
double mrpadd_time        = 0;
double muldvd_time        = 0;
double muldvd2_time       = 0;
double muldiv_time        = 0;
double muldvm_time        = 0;

double mrpsub_time		  = 0;
int muldvd2_count		  = 0;
int muldvd_count          = 0;
int muldiv_count 		  = 0;
int muldvm_count		  = 0;
int mrshift_count		  = 0;
int mr_shiftbits_count    = 0;

int mr_padd_op_1_len      = 0;
int mr_padd_op_2_len      = 0;
int mr_padd_op_3_len      = 0;
int mr_psub_op_1_len      = 0;
int mr_psub_op_2_len      = 0;
int mr_psub_op_3_len      = 0;

int redc_count			  = 0;
double redc_time		  = 0;

int mr_redc_op1_len;
int mr_redc_op2_len;
big monty_modulus;
mr_small monty_ndash;

struct timeval t1;
struct timeval t2;

int main()
{   
	PFC pfc(AES_SECURITY);  // initialize pairing-friendly curve

	/* Testing time */
	static double timeConvert = 0.0;
	mach_timebase_info_data_t timeBase;

	double istante1 = mach_absolute_time( ) ;


	cout<<"MR_MIP->base = "<<mr_mip->base<<endl;

	mad_count = 0;
	mult_g1_count = 0;
	mult_g2_count = 0;
	//miracl* mip=get_mip();

	time_t seed;

	/* Group element definition
	 * G1 and G2 are two distinct subgroups of a large group G, that is a group of prime that is cyclic.
	 * GT
	 * remember that the pairing pfc: G1,G2 -> GT
	 * In particular, these groups are subgroup of the group of points of an elliptic curve E(Fp) for a large prime p.
	 */
	int i,j;
	G1 g1,h1,h2;
	G2 g2,w;
	GT t1,t2,t3,t4;
	Big gamma;

	time(&seed);
    irand((long)seed); // Random value generation based on a time-based seed.
    /*
												███████╗███████╗████████╗██╗   ██╗██████╗
												██╔════╝██╔════╝╚══██╔══╝██║   ██║██╔══██╗
												███████╗█████╗     ██║   ██║   ██║██████╔╝
												╚════██║██╔══╝     ██║   ██║   ██║██╔═══╝
												███████║███████╗   ██║   ╚██████╔╝██║
												╚══════╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝


					On input of the security parameter 1t, the setup algorithm executes the following:

						1. Select three groups, G1,G2 and GT , of sufficiently large prime order p along
						   with a pairing ˆt : G1 × G2 → GT .
						   Select four random generators, P1, P2,P3 and Q, such that G1=<P1>=<P2>=<P3>
						   and G2 =<Q> and compute:
						   	   	   - T1 = ˆt(P1,Q)
						   	   	   - T2 = ˆt(P2,Q)
						   	   	   - T3 = ˆt(P3,Q).
						   Select five hash functions
								   - H1 : {0, 1}∗ → Zp,
								   - H2 : {0, 1}∗ → Zp,
								   - H3 : {0, 1}∗ → G1,
								   - H4 : {0, 1}∗ → Zp
						           - H5 : {0, 1}∗ → Zp.

						2. For each issuer i ∈ I, select an integer x ← Zp and compute:
						 	 	   - X = Q^x ∈ G2
						   	   	   - T4 = ˆt(P3,X).
						   The issuer secret key isk is assigned to be x and the
						   corresponding public key ipk is assigned to be X.

						3. For each TPM m ∈ M, select a sufficiently large integer DAAseed at random
						   (e.g. choose DAAseed from {0, 1}t) and keep it inside of the TPM secretly.

						4. Describe a DAA credential space C, a finite message space M and a finite
						   signature space Σ. The spaces C and Σ will be defined in the Join protocol
						   and Sign protocol respectively. The space M is dependent upon applications.

						5. Finally, the system public parameters par are set to be (G1, G2, GT , p, ˆt,
						   P1, P2, P3, Q, T1, T2, T3, T4, H1, H2, H3, H4, H5, ipk) together with C, M
						   and Σ, and are published.
   */
	cout << "Setup" << endl;

	Big order=pfc.order();

	/*
	 * pfc.random takes a random value, it is overloaded so if you put in a G1 value it gaves a random value from G1, same with G2.
	 * This isi because this library generates automatically the required three group required for the DAA implementation.
	 */

	// On the side of each function there is the adapted nomenclature

	pfc.random(g1); // g1 = P1;
	pfc.random(g2); // g2 = Q;
	pfc.random(gamma);  // sarebbe il p del doc di Chen: dovrebbe definire la dimensionalità del gruppo.
	pfc.random(h1); // h1 = P2;
	pfc.random(h2); // h2 = P3,
	w=pfc.mult(g2,gamma); // w = X (pubblica);

	t1=pfc.pairing(g2,g1);  // ^t(P1,Q)
	t2=pfc.pairing(g2,h1);  // ^t(P2,Q)
	t3=pfc.pairing(g2,h2);  // ^t(P3,Q)
	t4=pfc.pairing(w,h2);   // ^t(P3,X)


	pfc.precomp_for_mult(g1);
	pfc.precomp_for_mult(g2);
	pfc.precomp_for_mult(h1);
	pfc.precomp_for_mult(h2);
	pfc.precomp_for_mult(w);
	pfc.precomp_for_pairing(g2);
	pfc.precomp_for_power(t1);
	pfc.precomp_for_power(t2);
	pfc.precomp_for_power(t3);
	pfc.precomp_for_power(t4);

/*
														 ██╗ ██████╗ ██╗███╗   ██╗
														 ██║██╔═══██╗██║████╗  ██║
														 ██║██║   ██║██║██╔██╗ ██║
													██   ██║██║   ██║██║██║╚██╗██║
													╚█████╔╝╚██████╔╝██║██║ ╚████║
													 ╚════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝

	This phase is a communication between issuer and Host/TPM. An authenticated channel is established between the
	issuer and the host using the TPM Endorsment key pair (PK,SK). At each step the relative actor is indicated.

	A TPM DAA secret key f is computed from DAAseed along with a count number cnt and an issuer’s public data string KI.


 */
	cout << "Join" << endl;

	Big ni,f,sk,rf,c,sf,x,ci;
	G1 F,R;

	// ISSUER.
	pfc.random(ni);  // I: a random nonce is generated

	//ISSUER sends ni to TPM.

	// TPM
	pfc.random(f);   // should be H(DAASeed||cnt||KI), i do not modify this step for now.
	sk=f;  // <-- this is the secret.
	pfc.random(rf);  // rf = u randomly choosed from Zp
	F=pfc.mult(h1,f);  // F <- P2^f
	R=pfc.mult(h1,rf); // this is U <- P2^u

	// The TPM now starts the hash calculation.
	// H = (X || P1 || P2 || P3 || Q || ni || F || U) è il calcolo che viene eseguito in questi passaggi.
	pfc.start_hash();
	pfc.add_to_hash(order); pfc.add_to_hash(g1); pfc.add_to_hash(h1), pfc.add_to_hash(h2); pfc.add_to_hash(g2); pfc.add_to_hash(w);
	pfc.add_to_hash(ni); pfc.add_to_hash(F); pfc.add_to_hash(R);
	c=pfc.finish_hash_to_group(); // the result of the hash calculation

	sf=(rf+modmult(c,f,order))%order; // sf = w = u + f * v (mod p)

	//TPM sends comm={F,c,sf,ni} to Issuer

	//ISSUER
	// The Issuer should check ni is the same, and that F is not revoked (fake rogue list verification)
	G1 Rc,A;
	Rc=pfc.mult(h1,sf)+pfc.mult(F,-c); // Rc is the R value recalculated (the paper calls it U').
	pfc.start_hash(); // ISSUER verifies the hash result
	pfc.add_to_hash(order); pfc.add_to_hash(g1); pfc.add_to_hash(h1), pfc.add_to_hash(h2); pfc.add_to_hash(g2); pfc.add_to_hash(w);
	pfc.add_to_hash(ni); pfc.add_to_hash(F); pfc.add_to_hash(Rc); ci=pfc.finish_hash_to_group();

	//Hash result verification
	if (ci!=c)
	{
		cout << "Verification fails, aborting.. " << endl;
		exit(0);
	}

	pfc.random(x);  // x is the credential!!!

	A=pfc.mult(g1+F,inverse(x+gamma,order)); // A è A del paper.
	
	// ISSUER sends credential cre={A,x} to TPM

	// TPM forwards F and cre to Host

	//HOST (as shown in paper Join figure)

	G2 wxg2=w+pfc.mult(g2,x);
	G1 g1f=-(F+g1);

	G1 *gf1[2];
	G2 *gf2[2];
	gf1[0]=&A;
	gf1[1]=&g1f;
	gf2[0]=&wxg2;
	gf2[1]=&g2;

	if (pfc.multi_pairing(2,gf2,gf1)!=1)  // <-- questa funzione l'ho copiata, fa il confronto tra due funzioni di pairing!!
	{
		cout << "Verification fails, aborting.. " << endl;
		exit(0);
	}

	/*
														███████╗██╗ ██████╗ ███╗   ██╗
														██╔════╝██║██╔════╝ ████╗  ██║
														███████╗██║██║  ███╗██╔██╗ ██║
														╚════██║██║██║   ██║██║╚██╗██║
														███████║██║╚██████╔╝██║ ╚████║
														╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝


			This step is a communication between the Host and TPM in order to produce a DAA signature on some message. The TPM
			is the REAL signer and the Host is only an helper.
	 */
	cout << "Sign" << endl;

	G1 B,K,R1,R2t,nv;

	//VERIFIER
	pfc.random(nv); // called nv into the paper.

	// The verifier sends nv to TPM

	//TPM
	pfc.hash_and_map(B,(char *)"bsn"); //basename hashing. B is a G1 element. Called J into paper

	pfc.random(rf); //picks a random value rf from Zp group

	K=pfc.mult(B,f); // K = J^f
	R1=pfc.mult(B,rf); // called L into paper R1 = J^rf
	R2t=pfc.mult(h1,rf);

	// TPM sends B, K, R1, R2t to Host

	//HOST
	G1 T;
	GT R2;
	Big a,b,rx,ra,rb,ch,nt;
	pfc.random(a); //from Zp (Zp is the a group with big number probably order "order")).
	b=modmult(a,x,order);
	T=A+pfc.mult(h2,a);
	pfc.random(rx);
	pfc.random(ra);
	pfc.random(rb);

	R2=pfc.pairing(g2,R2t+pfc.mult(T,-rx)+pfc.mult(h2,rb))*pfc.power(t4,ra);

	pfc.start_hash();
	pfc.add_to_hash(order); pfc.add_to_hash(g1); pfc.add_to_hash(h1), pfc.add_to_hash(h2); pfc.add_to_hash(g2); pfc.add_to_hash(w);
	pfc.add_to_hash(B); pfc.add_to_hash(K); pfc.add_to_hash(T); pfc.add_to_hash(R1); pfc.add_to_hash(R2); pfc.add_to_hash(nv);
	ch=pfc.finish_hash_to_group();

	//HOST sends ch to TPM

	// TPM does..
	pfc.random(nt); // generates a random nt
	pfc.start_hash(); pfc.add_to_hash(ch); pfc.add_to_hash(nt); pfc.add_to_hash((char *)"Test message to be signed");
	c=pfc.finish_hash_to_group();
	sf=(rf+modmult(c,f,order))%order;
// {c,nt,sf) sent to Host
	rf=0; // rf is erased. rf is erased in order to prevent REPLAY ATTACKS.

	//HOST
	Big sx,sa,sb;
	sx=(rx+modmult(c,x,order))%order;
	sa=(ra+modmult(c,a,order))%order;
	sb=(rb+modmult(c,b,order))%order;

	// Host outputs signature {B,K,T,c,nt,sf,sx,sa,sb} to VERIFIER (if required)
/*

											██╗   ██╗███████╗██████╗ ██╗███████╗██╗   ██╗
											██║   ██║██╔════╝██╔══██╗██║██╔════╝╚██╗ ██╔╝
											██║   ██║█████╗  ██████╔╝██║█████╗   ╚████╔╝
											╚██╗ ██╔╝██╔══╝  ██╔══██╗██║██╔══╝    ╚██╔╝
											 ╚████╔╝ ███████╗██║  ██║██║██║        ██║
											  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝


 */
	cout << "Verify" << endl;

	G1 R1c;
	GT R2c;
	Big cc;
	R1c=pfc.mult(B,sf)+pfc.mult(K,-c);

	R2c=pfc.pairing(pfc.mult(g2,-sx)+pfc.mult(w,-c),T)*pfc.power(t1,c)*pfc.power(t2,sf)*pfc.power(t3,sb)*pfc.power(t4,sa);

	pfc.start_hash();
	pfc.add_to_hash(order); pfc.add_to_hash(g1); pfc.add_to_hash(h1), pfc.add_to_hash(h2); pfc.add_to_hash(g2); pfc.add_to_hash(w);
	pfc.add_to_hash(B); pfc.add_to_hash(K); pfc.add_to_hash(T); pfc.add_to_hash(R1c); pfc.add_to_hash(R2c); pfc.add_to_hash(nv);
	ch=pfc.finish_hash_to_group();
	pfc.start_hash(); pfc.add_to_hash(ch); pfc.add_to_hash(nt); pfc.add_to_hash((char *)"Test message to be signed");
	cc=pfc.finish_hash_to_group();

	if (cc==c)
		cout << "Verification succeeds! " << endl;
	else
		cout << "Verification fails, aborting.. " << endl;

	cout<<"Stats:"<<endl;
	cout<<"\t MAD: "<<mad_count<<endl;
	cout<<"\t MULT_G1: "<<mult_g1_count<<endl;
	cout<<"\t MULT_G2: "<<mult_g2_count<<endl;
	cout<<"\t HASH: "<<hash_count<<endl;
	cout<<"\t MR_PADD: "<<mrpadd_count<<"||  Max Time: "<<mrpadd_time<<"|| Input Dim Op1 (byte):" <<mr_padd_op_1_len*8<<"|| Input Dim Op2 (byte):" <<mr_padd_op_2_len*8<<"|| Input Dim Result (byte):" <<mr_padd_op_3_len*8<<endl;
	cout<<"\t MR_PSUB: "<<mrpsub_count<<"||  Max Time: "<<mrpsub_count<<"|| Input Dim Op1 (byte):" <<mr_psub_op_1_len*8<<"|| Input Dim Op2 (byte):" <<mr_psub_op_2_len*8<<"|| Input Dim Result (byte):" <<mr_psub_op_3_len*8<<endl;
	cout<<"\t MULDIV: "<<muldiv_count<<"||  Max Time: "<<muldiv_time<<endl;
	cout<<"\t MULDVD: "<<muldvd_count<<"||  Max Time: "<<muldvd_time<<endl;
	cout<<"\t MULDVD2: "<<muldvd2_count<<"||  Max Time: "<<muldvd2_time<<endl;
	cout<<"\t MULDVM: "<<muldvm_count<<"|| Max Time: "<<muldvm_time<<endl;
	cout<<"\t REDC:"<<redc_count<<"|| Max Time: "<<redc_time<<"|| Input Dim Op1 (byte):" <<mr_redc_op1_len*8<<"|| Input Dim Op2 (byte):" <<mr_redc_op2_len*8<<endl;

	cout<<"MR->MIP W0 : "<<mr_mip->w0<<endl;
	cout<<"Monty Modulus lenght : "<<mr_mip->modulus->len<<endl;

	cout<<"Monty Modululus : "<<mr_mip->modulus<<endl;
	cout<<"Monty NDASH : "<<mr_mip->ndash<<endl;


    double istante2 = mach_absolute_time( );


	cout<<"Tempo totale MIRACL su MACOSX = "<<istante2-istante1<<endl;
    return 0;
}
