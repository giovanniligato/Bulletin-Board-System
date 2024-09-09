---
header-includes: |
    \usepackage{graphicx}
    \usepackage{seqsplit}
    \usepackage{fvextra}
    \DefineVerbatimEnvironment{Highlighting}{Verbatim}{breaklines,commandchars=\\\{\}}
    \usepackage{caption}
    \usepackage{subcaption}
    \usepackage{xcolor}
    \usepackage{lscape}

    \usepackage{tabularx}
    \usepackage{booktabs}
    \usepackage{caption}
    \usepackage{geometry}
    \usepackage{xltabular}
    \usepackage{tikz}


---


\title{Foundations of Cybersecurity}

\begin{figure}[!htb]
    \centering
    \includegraphics[keepaspectratio=true,scale=0.4]{Resources/"cherub.eps"}
\end{figure}

\begin{center}
    \LARGE{UNIVERSITY OF PISA}
    \vspace{5mm}
    \\ \large{MASTER'S DEGREE IN COMPUTER ENGINEERING}\vspace{3mm}
    \\ \large{Foundations of Cybersecurity}
    \vspace{15mm}
    \\ \LARGE\textbf{Bulletin-Board-System}
\end{center}

\vspace{25mm}

\begin{minipage}[t]{0.47\textwidth}
	{\large{Professor:}{\normalsize\vspace{3mm} \bf\\ \large{Gianluca Dini} }}
\end{minipage}
\hfill
\begin{minipage}[t]{0.47\textwidth}\raggedleft
 {\large{Student:}\raggedleft
 {\normalsize\vspace{3mm}
	\bf\\ \large{Giovanni Ligato}\raggedleft }}
\end{minipage}

\vspace{45mm}

\hrulefill

\begin{center}
\normalsize{ACADEMIC YEAR 2023/2024}
\end{center}

\pagenumbering{gobble}

\renewcommand*\contentsname{Index}
\tableofcontents


\newpage

\pagenumbering{arabic}

# 1. Introduction

The system under study is a Bulletin Board System (BBS), a distributed service where users can read messages and add their own. In particular BBS provides users with the following operations:
- List(int n) which lists the latest n available messages in the BBS. 
- - Get(int mid) which downloads from the BBS the message specified by
message identifier mid.
- Add(String title, String author, String body) which adds a
message to the BBS.
Registered users may issue operations after successful login. Operations are executed over a secure channel. A user who logs out cannot perform operations until (s)he successfully logs in again.

Before that a user is allowed to perform the previous operations it is necessary to correctly login into the system. Furthermore, if the user is not registered, (s)he must first register to the system. 

# 2. System Specification

Here are all the details related to all the entities involved in the system. Hypotheses and requirements are also specified.

## Server

The BBS server is a centralized entity that handles in a multi-threaded, and secure way all the requests coming from the clients. The server is attested at a well-known (ip, port) couple. Furthermore, the BBS server is equipped with a private-public key pair of which the public component pubK bbs is known to users. So all the clients know the public key of the server, this is one of the main assumptions of the system, that allows to simplify the protocol used for establishing a secure channel between the client and the server, where both share a secret key that will be used for encrypting and decrypting the messages exchanged between them.

## User

THe users are those that will utilize the clients to interact with the server. Each user is identified by means of a nickname that is established at registration time together with a password. The password is never stored or transmitted in the clear. The user is also associated with an email address that simulates a secure channel, sent by the server in the registration phase. For simulating the secure channel in order to authenticate the user with his email address, the server will write the challenge inside the Storage of the clients in the emails folder, in  a file named as the email address of the user. The client will read the challenge from the file, as if it was sent by email. An example will clarify this concept. If the mail of the user is `user123@gmail.com`, the server will write the challenge inside the file `Client\Storage\Emails\user123@gmail.com.txt`. The client will read the challenge from the file and paste it to the terminal enabling the registration phase to correctly conclude.


## Message

A message is a tuple composed of the following fields: identifier, title, author, and body. The identifier field uniquely identifies the message within the BBS. The author field specifies the nickname of the user who added the message to the BBS.


## Secure Channel

When the clients are started, a simple TCP connection between the particular client and the only server of The BBS is established. It is clear that using such a connection is not secure, becuase an attacker could exploit this channel to:
- eavesdrop the messages exchanged between the client and the server, breaking the confidentiality requirement.
- modify the messages exchanged between the client and the server, breaking the integrity requirement.
- replay the messages exchanged between the client and the server, breaking the no-replay requirement.
- modify the messages exchanged between the client and the server, breaking the non-malleability requirement.
So to fulfill to those requiremnts it is necessary to  establish a secure channel by means of a proper defined security protocol. The protocol that is implemented before the transmission of each packet to the server is the one described in the figure x.
Here going into the details there is a first message, M1 that the client sends to the server. This message is composed of two different packets,
as the first one is just the encryption by public key of the server of a client generated authentication key (i.e. `authK`) used just for authentication purposes. Being encrypted by the public key of the server, the only one that can read it is the server and obviously the client that generated it. Using that key, now the client makes use of AE, that is an Authenticated Encryption method that follows these details:

When specifying both the Additional Authenticated Data (AAD) and the plaintext in the context of authenticated encryption, you can use a notation that includes both components. The notation should clearly differentiate between the AAD and the plaintext (or message) being encrypted. Here’s how you might represent this:

### General Notation

For authenticated encryption with AAD, the notation might be:

\[
\text{AE}_{K}(\text{AAD}, \text{Plaintext}) = (\text{Ciphertext}, \text{Tag})
\]

where:
- **\(\text{AE}_{K}\)** denotes the authenticated encryption operation with key \( K \).
- **\(\text{AAD}\)** represents the additional authenticated data.
- **\(\text{Plaintext}\)** represents the data being encrypted.
- **\(\text{Ciphertext}\)** is the result of encrypting the plaintext.
- **\(\text{Tag}\)** is the authentication tag used to verify both the ciphertext and the AAD.

In the figure there are only AAD, as the Plaintext is not sent to the server. Here there's no need to encrypt g^a mod p and N_A because we only want that the integrity of them is preserved and this is the case as the AE method computes the tag associated to those quantities, that the server will check at the destination and if the tag is correct, the server will be sure that the values of g^a mod p and N_A are the same as the ones sent by the client. 

Now the server after receiving M1, and decrypting authJ with its private key, it can compute the tag of the second packet of M1 and check if it is the same as the one sent by the client. If it is the same, the server will be sure that the client is the one that sent the message and that the message has not been modified by an attacker. Now the server will prepare M2, where it will put his counterpart of the public key of the Diffie Hellman key exchange, i.e. g^b mod p. It will append also the N_A of the client to the AAD and authenticate and encrypt the packet with the same AE method. The client will receive M2, and after decrypting it with the session key, it will check the tag and if it is correct, it will be sure that the server is the one that sent the message and that the message has not been modified by an attacker. The client will also check that the N_A is the same as the one sent by the client in M1. Otherwise a replay attack would have been happened. 

Note that sending the same M1 will result in general in a different M2 and hence in a different share key, aas g^b mod p is chosen by the server and hence is like a nonce, because the same session key can't be forced by the attacker to be used in another session, because the attacker can't know the value of g^b mod p before the server sends it to the client. And in general it will be different. Replay attacks from the server are neither possible as before said because the N_A is different in each session and the server can't know the value of N_A before the client sends it to the server. 

After having received correctly g^b mod p the client and g^a mod p the server, they can compute the shared key that will be used for encrypting and decrypting the messages exchanged between them. Before that of course the shared secred is hashed as it is a good practice to do that, before using the shared secret as a simmetric key for the encryption and decryption of the messages. The hash function used is SHA256.
The autentication encryption used instead is the AES 128 GCM, that is a good choice for the encryption of the messages exchanged between the client and the server, as it is a secure and efficient method for the encryption and decryption of the messages and furthermore there is no expansion of the ciphertext with regard to the plaintext The details of the packets exchanged in the secure channel are the following:

First packet:

\begin{tikzpicture}
    % Draw the blocks using relative lengths
    \draw (0, 0) rectangle (\textwidth, 1) node[midway] { $\{AUTH\_KEY\}_{pubK_S}$ };
    % Labels for the bits
    \node at (0.5\textwidth, -0.3) {256}; % Adjust position relative to the total width
\end{tikzpicture}


Second packet of m1 and also m2

\begin{tikzpicture}
    % Draw the blocks using relative lengths
    \draw (0, 0) rectangle (0.1\textwidth, 1) node[midway] {IV};
    \draw (0.1\textwidth, 0) rectangle (0.85\textwidth, 1) node[midway] {AAD};
    \draw (0.85\textwidth, 0) rectangle (\textwidth, 1) node[midway] {TAG};
    % Labels for the bits - Center the labels
    \node at (0.05\textwidth, -0.3) {12};
    \node at (0.475\textwidth, -0.3) {670};
    \node at (0.925\textwidth, -0.3) {16};
\end{tikzpicture}

In Aad there are both the public key of Diffie Hellman (654 bytes) and concatenated to it the nonce of the client (16 bytes). 




Registration Phase
● A user securely connects to the BBS server and specifies an email address, a
nickname and a password;
● the server sends a challenge to the email address specified by the user and
waits for receiving the challenge back;
● if the user correctly returns the challenge to the server, the registration phase
concludes successfully. Otherwise, it is aborted.
Login phase
● A registered user securely connects to the BBS server and logins by means of
his/her nickname and password.
● The server lets the user log in if the submitted user’s nickname and password are
correctly verified.
● Upon successful login, a secure session is established and maintained until the
user logs out.



Requirements
● Never store or transmit passwords in the clear. ● Fulfill confidentiality, integrity, no-replay, and non-malleability in communications. ● Guarantee perfect forward secrecy (PFS).
● Reduce code vulnerabilities as much as possible. ● Use C or C++ programming language and OpenSSL library but OpenSSL API
TLS cannot be used.
Deliverables
● System specification and design. ● A running early prototype.

----



\begin{center}
\begin{tikzpicture}
    % Disegno dei blocchi
    \draw (0, 0) rectangle (3, 1) node[midway] {NONCE};
    \draw (3, 0) rectangle (6, 1) node[midway] {PKT\_TYPE};
    \draw (6, 0) rectangle (12, 1) node[midway] {DATA};
    % Etichette per i bit
    \node at (0, -0.5) {0};
    \node at (3, -0.5) {7};
    \node at (6, -0.5) {15};
    \node at (12, -0.5) {273};
\end{tikzpicture}
\end{center}



This is the general packets format exchanged during all the subsequent phases after that the secure connection is established.


\begin{tikzpicture}
    % Draw the blocks using relative lengths
    \draw (0, 0) rectangle (0.05\textwidth, 1) node[midway] {IV};
    \draw (0.05\textwidth, 0) rectangle (0.25\textwidth, 1) node[midway] {AAD\_SIZE};
    \draw (0.25\textwidth, 0) rectangle (0.45\textwidth, 1) node[midway] {AAD};
    \draw (0.45\textwidth, 0) rectangle (0.65\textwidth, 1) node[midway] {CIPH\_SIZE};
    \draw (0.65\textwidth, 0) rectangle (0.9\textwidth, 1) node[midway] {CIPH};
    \draw (0.9\textwidth, 0) rectangle (\textwidth, 1) node[midway] {TAG};
    % Labels for the bits
    \node at (0.025\textwidth, -0.3) {12};        % Centered under IV
    \node at (0.15\textwidth, -0.3) {4};          % Centered under AAD_SIZE
    \node at (0.35\textwidth, -0.3) {AAD\_SIZE};   % Centered under AAD
    \node at (0.55\textwidth, -0.3) {4};          % Centered under CIPH_SIZE
    \node at (0.775\textwidth, -0.3) {CIPH\_SIZE}; % Centered under CIPH
    \node at (0.95\textwidth, -0.3) {16};         % Centered under TAG
\end{tikzpicture}


// Possible values for type:
#define T_REGISTRATION 1
#define T_LOGIN 2
#define T_OK 3
#define T_KO 4
#define T_LIST 5
#define T_GET 6
#define T_ADD 7
#define T_LOGOUT 8







Hp: 
p and g are public known
and also the server's public key is know to all clients











<!-- A visual result from U-Net is shown in Figure \ref{fig:unet_masks}, using the best model weights from the first round on the same image as the YOLO model. -->

<!-- \begin{figure}
    \centering
    \includegraphics[width=0.65\textwidth]{Resources/"U-Net_834_glioma_prediction.png"}
    \caption{Predicted mask by U-Net. The tumor being segmented is a Glioma, with a Dice similarity score of 0.785. Inference was performed using the best model weights from the first round of the U-Net model on image number 834 of the test set.}
    \label{fig:unet_masks}
\end{figure} -->
