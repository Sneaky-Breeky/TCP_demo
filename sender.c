/************************************************************************
 * Adapted from a course at Boston University for use in CPSC 317 at UBC
 *
 *
 * The interfaces for the STCP sender (you get to implement them), and a
 * simple application-level routine to drive the sender.
 *
 * This routine reads the data to be transferred over the connection
 * from a file specified and invokes the STCP send functionality to
 * deliver the packets as an ordered sequence of datagrams.
 *
 * Version 2.0
 *
 *
 *************************************************************************/


#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <time.h>

#include "stcp.h"

#define STCP_SUCCESS 1
#define STCP_ERROR -1

typedef struct {
    /* YOUR CODE HERE */
    int fd;
    int curr_window_size;
    int state;
    unsigned int seq;
    unsigned int ack;
} stcp_send_ctrl_blk;
/* ADD ANY EXTRA FUNCTIONS HERE */

// generate a random sequence number from 0 to 2^32 - 1
unsigned int random_seq(){
    srand(time(NULL));
    unsigned int seqNum = rand();

    return seqNum;
}

// concatenate tcp header and payload to a new char array
// void *makePacket(packet *pkt) {
//     memcpy(pkt->hdr + sizeof(tcpheader), pkt->data, payloadSize(pkt));
// }

// set the checksum
void setChecksum(tcpheader *seg, int len) {
    tcpheader *hdr = (tcpheader *)seg;
    hdr->checksum = ipchecksum(seg, len);
}

void sendPacket(packet *pkt, int fd, unsigned char *data, int len) {
    // makePacket(pkt);
    memcpy((packet*)((char*)pkt + (pkt->len - payloadSize(pkt))), data, len);
    htonHdr(pkt->hdr);

    setChecksum(pkt->hdr, pkt->len);

    write(fd, pkt->hdr, pkt->len);
}

int checksumCorrect(unsigned char *recv, int synLen) {
    // tcpheader *hdr = (tcpheader *)recv;
    // return hdr->checksum == ipchecksum(recv, synLen)? 1 : 0;
    return ipchecksum(recv, synLen) == 0? 1 : 0;
}


/*
 * Send STCP. This routine is to send all the data (len bytes).  If more
 * than MSS bytes are to be sent, the routine breaks the data into multiple
 * packets. It will keep sending data until the send window is full or all
 * the data has been sent. At which point it reads data from the network to,
 * hopefully, get the ACKs that open the window. You will need to be careful
 * about timing your packets and dealing with the last piece of data.
 *
 * Your sender program will spend almost all of its time in either this
 * function or in tcp_close().  All input processing (you can use the
 * function readWithTimeout() defined in stcp.c to receive segments) is done
 * as a side effect of the work of this function (and stcp_close()).
 *
 * The function returns STCP_SUCCESS on success, or STCP_ERROR on error.
 */
int stcp_send(stcp_send_ctrl_blk *stcp_CB, unsigned char* data, int length) {
    /* YOUR CODE HERE */
    if (stcp_CB == NULL) return STCP_ERROR;

    int timeout = STCP_MIN_TIMEOUT;
    packet *pkt = malloc(sizeof(packet));
    unsigned char *recv = malloc(sizeof(tcpheader));
    createSegment(pkt, ACK, stcp_CB->curr_window_size, stcp_CB->seq, stcp_CB->ack, data, length);

    do {
        memset(recv, 0, sizeof(tcpheader));
        
        sendPacket(pkt, stcp_CB->fd, data, length);
        
        // receive ACK
        int synLen = readWithTimeout(stcp_CB->fd, recv, timeout);
        if (synLen == STCP_READ_TIMED_OUT) {
            logPerror("STCP_READ_TIMED_OUT");
            timeout = stcpNextTimeout(timeout);
            continue;
        } else if (synLen == STCP_READ_PERMANENT_FAILURE) {
            logPerror("STCP_READ_PERMANENT_FAILURE");
            return STCP_ERROR;
        } else if (!checksumCorrect(recv, synLen)) {
            logPerror("INCORRECT_CHECKSUM");
            continue;
        }

        ntohHdr((tcpheader *)recv);
        // update window size
        if (((tcpheader *)recv)->windowSize != stcp_CB->curr_window_size) {
            stcp_CB->curr_window_size = ((tcpheader *)recv)->windowSize;
        }

        if (stcp_CB->seq == ((tcpheader *)recv)->ackNo) {
            logPerror("IDENTICAL_SEQ_NUM");
            continue;
        } else if (((tcpheader *)recv)->ackNo != stcp_CB->seq + length) {
            logPerror("BAD_ACK");
            continue;
        }

        printf("number: %d %d\n",((tcpheader *)recv)->ackNo,((tcpheader *)recv)->seqNo + length);

        stcp_CB->seq = ((tcpheader *)recv)->ackNo;
        stcp_CB->ack = ((tcpheader *)recv)->seqNo + length;

    } while(0);
    
    free(pkt);
    free(recv);

    return STCP_SUCCESS;
}



/*
 * Open the sender side of the STCP connection. Returns the pointer to
 * a newly allocated control block containing the basic information
 * about the connection. Returns NULL if an error happened.
 *
 * If you use udp_open() it will use connect() on the UDP socket
 * then all packets then sent and received on the given file
 * descriptor go to and are received from the specified host. Reads
 * and writes are still completed in a datagram unit size, but the
 * application does not have to do the multiplexing and
 * demultiplexing. This greatly simplifies things but restricts the
 * number of "connections" to the number of file descriptors and isn't
 * very good for a pure request response protocol like DNS where there
 * is no long term relationship between the client and server.
 */
 // destination = destination host
stcp_send_ctrl_blk * stcp_open(char *destination, int sendersPort,
                             int receiversPort) {

    logLog("init", "Sending from port %d to <%s, %d>", sendersPort, destination, receiversPort);
    // Since I am the sender, the destination and receiversPort name the other side
    int fd = udp_open(destination, receiversPort, sendersPort);
    (void) fd;
    /* YOUR CODE HERE */
    stcp_send_ctrl_blk *cb = malloc(sizeof(stcp_send_ctrl_blk));
    cb->state = STCP_SENDER_SYN_SENT;
    cb->curr_window_size = 0;
    cb->fd = (int) fd;
    cb->seq = random_seq();

    // STCP three-way handshake
    do {
        // 1. send SYN packet to server
        packet *pkt = malloc(sizeof(packet));
        createSegment(pkt, SYN, STCP_MAXWIN, cb->seq, 0, NULL, 0);

        sendPacket(pkt, cb->fd, NULL, 0);

        // 2. receive SYN/ACK from server
        unsigned char *recv = malloc(STCP_MTU);

        int synLen = readWithTimeout(cb->fd, recv, STCP_MIN_TIMEOUT);

        if (synLen == STCP_READ_TIMED_OUT) {
            logPerror("STCP_READ_TIMED_OUT");
            continue;
        } else if (synLen == STCP_READ_PERMANENT_FAILURE) {
            logPerror("STCP_READ_PERMANENT_FAILURE");
            return NULL;
        } else if (!checksumCorrect(recv, synLen)) {
            logPerror("INCORRECT_CHECKSUM");
            continue;
        }

        ntohHdr((tcpheader *)recv);

        // check ack
        if (((tcpheader *)recv)->ackNo != cb->seq + 1) {
            logPerror("BAD_ACK");
            continue;
        }

        // update window size
        if (((tcpheader *)recv)->windowSize != cb->curr_window_size) {
            cb->curr_window_size = ((tcpheader *)recv)->windowSize;
        }

        // 3. send ACK packet to server
        cb->seq = ((tcpheader *)recv)->ackNo;
        cb->ack = ((tcpheader *)recv)->seqNo + 1;
        packet *pktAck = malloc(sizeof(packet));
        createSegment(pktAck, ACK, cb->curr_window_size, cb->seq, cb->ack, NULL, 0);
        memset(recv, 0, STCP_MTU);
        sendPacket(pktAck, cb->fd, NULL, 0);
        readWithTimeout(cb->fd, recv, STCP_MAX_TIMEOUT);

        // if ACK(third handshake) is lost
        // while (readWithTimeout(cb->fd, recv, STCP_MAX_TIMEOUT) != STCP_READ_TIMED_OUT) {
        //     sendPacket(pktAck, cb->fd);
        // }

        free(pkt);
        free(pktAck);
        free(recv);
    } while (0);

    cb->state = STCP_SENDER_ESTABLISHED;
    return cb;
}


/*
 * Make sure all the outstanding data has been transmitted and
 * acknowledged, and then initiate closing the connection. This
 * function is also responsible for freeing and closing all necessary
 * structures that were not previously freed, including the control
 * block itself.
 *
 * Returns STCP_SUCCESS on success or STCP_ERROR on error.
 */
int stcp_close(stcp_send_ctrl_blk *cb) {
    /* YOUR CODE HERE */
    if (cb == NULL) return STCP_ERROR;

    // outstanding data has been transmitted and acknowledged

    // close connection
    int timeout = STCP_MIN_TIMEOUT;
    do {
        // 1. send SYN packet to server
        packet *pkt = malloc(sizeof(packet));
        createSegment(pkt, FIN, cb->curr_window_size, cb->seq, cb->ack, NULL, 0);

        sendPacket(pkt, cb->fd, NULL, 0);

        // 2. receive FIN/ACK from server
        unsigned char *recv = malloc(STCP_MTU);

        int finLen = readWithTimeout(cb->fd, recv, timeout);

        if (finLen == STCP_READ_TIMED_OUT) {
            timeout = stcpNextTimeout(timeout);
            logPerror("STCP_READ_TIMED_OUT");
            continue;
        } else if (finLen == STCP_READ_PERMANENT_FAILURE) {
            logPerror("STCP_READ_PERMANENT_FAILURE");
            return STCP_ERROR;
        } else if (!checksumCorrect(recv, finLen)) {
            logPerror("INCORRECT_CHECKSUM");
            continue;
        }

        ntohHdr((tcpheader *)recv);
        if (((tcpheader *)recv)->flags != (FIN | ACK)) {
            logPerror("NOT_FINACK");
            continue;
        }

        // 3. send ACK packet to server
        cb->seq = ((tcpheader *)recv)->ackNo, cb->ack = ((tcpheader *)recv)->seqNo + 1;
        packet *pktAck = malloc(sizeof(packet));
        createSegment(pktAck, ACK, cb->curr_window_size, cb->seq, cb->ack, NULL, 0);
        memset(recv, 0, STCP_MTU);
        sendPacket(pktAck, cb->fd, NULL, 0);

        // if ACK(third handshake) is lost
        // while (readWithTimeout(cb->fd, recv, STCP_MAX_TIMEOUT) != STCP_READ_TIMED_OUT) {
        //     sendPacket(pktAck, cb->fd);
        // }

        free(pkt);
        free(pktAck);
        free(recv);
    } while (0);

    // close cb
    close(cb->fd);

    // free cb
    free(cb);

    return STCP_SUCCESS;
}
/*
 * Return a port number based on the uid of the caller.  This will
 * with reasonably high probability return a port number different from
 * that chosen for other uses on the undergraduate Linux systems.
 *
 * This port is used if ports are not specified on the command line.
 */
int getDefaultPort() {
    uid_t uid = getuid();
    int port = (uid % (32768 - 512) * 2) + 1024;
    assert(port >= 1024 && port <= 65535 - 1);
    return port;
}

/*
 * This application is to invoke the send-side functionality.
 */
int main(int argc, char **argv) {
    stcp_send_ctrl_blk *cb;

    char *destinationHost;
    int receiversPort, sendersPort;
    char *filename = NULL;
    int file;
    /* You might want to change the size of this buffer to test how your
     * code deals with different packet sizes.
     */
    unsigned char buffer[STCP_MSS];
    int num_read_bytes;

    logConfig("sender", "init,segment,error,failure");
    /* Verify that the arguments are right */
    if (argc > 5 || argc == 1) {
        fprintf(stderr, "usage: sender DestinationIPAddress/Name receiveDataOnPort sendDataToPort filename\n");
        fprintf(stderr, "or   : sender filename\n");
        exit(1);
    }

    
    if (argc == 2) {
        filename = argv[1];
        argc--;
    }

    // Extract the arguments
    destinationHost = argc > 1 ? argv[1] : "localhost";
    receiversPort = argc > 2 ? atoi(argv[2]) : getDefaultPort();
    sendersPort = argc > 3 ? atoi(argv[3]) : getDefaultPort() + 1;
    if (argc > 4) filename = argv[4];

    /* Open file for transfer */
    // read only
    file = open(filename, O_RDONLY);
    if (file < 0) {
        logPerror(filename);
        exit(1);
    }

    /*
     * Open connection to destination.  If stcp_open succeeds the
     * control block should be correctly initialized.
     */
    cb = stcp_open(destinationHost, sendersPort, receiversPort);
    if (cb == NULL) {
        /* YOUR CODE HERE */
        logPerror("stcp_open");
        exit(1);
    }

    /* Start to send data in file via STCP to remote receiver. Chop up
     * the file into pieces as large as max packet size and transmit
     * those pieces.
     */
    while (1) {
        num_read_bytes = read(file, buffer, sizeof(buffer));

        /* Break when EOF is reached */
        if (num_read_bytes <= 0) {
            cb->state = STCP_SENDER_CLOSING;
            break;
        }

        if (stcp_send(cb, buffer, num_read_bytes) == STCP_ERROR) {
            /* YOUR CODE HERE */
            logPerror("stcp_send");
            exit(1);
        }
    }

    /* Close the connection to remote receiver */
    if (stcp_close(cb) == STCP_ERROR) {
        /* YOUR CODE HERE */
        logPerror("stcp_close");
        exit(1);
    }

    return 0;
}
