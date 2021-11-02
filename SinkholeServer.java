package il.ac.idc.cs.sinkhole;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashSet;

public class SinkholeServer {
	private static final int SinkholeServerPort = 5300;
	private static final int DNSPort = 53;
	private static final int numberOfRootServers = 13;
	private static final int limitOfIterations = 16;
	private static final int numberOfBytesInHeader = 12;
	private static final int firstByteOfFlagsInHeader = 2;
	private static final int secondByteOfFlagsInHeader = 3;
	private static final int firstByteOfNumOfAnswerRRs = 6;
	private static final int firstByteOfNumOfAuthorityRRs = 8;
	private static final int numOfBitsInByte = 8;
	private static final int dotInAscii = 46;
	private static InetAddress[] rootServers = new InetAddress[numberOfRootServers];
	private static InetAddress hostIP;
	private static int hostPort;
	private static int pointer; 

	public static void main(String[] args){
		byte[] receiveDataFromServer = new byte[1024];
		DatagramSocket serverSocket = null;
		DatagramSocket clientSocket = null;
		HashSet<String> blockList = new HashSet<String>();
	
		if(args.length == 1) {
			String pathOfTextFile = args[0];
			blockList = convertBlockListToHashSet(pathOfTextFile);
		}
		
		try {
			serverSocket = new DatagramSocket(SinkholeServerPort);
		} catch (SocketException e) {
			System.err.printf("Problem with opening the server socket");
			return;
		}

		initRootServersArray();

		while (true) {
			byte[] dataFromClient = new byte[1024];
			boolean isValidDomainName = true;
			String queryDomainName = "";
			try {
				clientSocket = new DatagramSocket();
			} catch (SocketException e) {
				System.err.printf("Problem with opening the client socket");
				break;
			}
			
			DatagramPacket receivePacketFromClient = new DatagramPacket(dataFromClient, dataFromClient.length);
			try {
				serverSocket.receive(receivePacketFromClient); // Receive query from the client.
			} catch (IOException e) {
				System.err.printf("Problem while receiving packet from the client");
				break;
			}
			
			dataFromClient = handlePacketFromClient(receivePacketFromClient);
			queryDomainName = createAddressString(numberOfBytesInHeader, dataFromClient);
			
			if(blockList.contains(queryDomainName)) {
				isValidDomainName = false;
				sendPacketToClient(dataFromClient, isValidDomainName, serverSocket);
			} else {
				InetAddress currentAddress = getRandomRootServer();
	
				for (int i = 0; i < limitOfIterations; i++) {
					byte flagResponseCode;
					char numberOfAnswerRecords;
					char numberOfAuthorityRecords;
					
					DatagramPacket packetToServer = new DatagramPacket(dataFromClient, dataFromClient.length, currentAddress, DNSPort);
					try {
						clientSocket.send(packetToServer);
					} catch (IOException e) {
						System.err.printf("Problem with sending packet to server");
						System.exit(1);
					}
					receiveDataFromServer = new byte[1024];
					DatagramPacket packetFromServer = new DatagramPacket(receiveDataFromServer, receiveDataFromServer.length);
					try {
						clientSocket.receive(packetFromServer);
					} catch (IOException e) {
						System.err.printf("Problem with receiving packet from server");
						System.exit(1);
					}
					receiveDataFromServer = Arrays.copyOfRange(receiveDataFromServer, 0, packetFromServer.getLength());
					pointer = 0;
	
					flagResponseCode = getFlagResponseCode(receiveDataFromServer);
					numberOfAnswerRecords = getTwoConsecutiveBytes(receiveDataFromServer, firstByteOfNumOfAnswerRRs);
					numberOfAuthorityRecords = getTwoConsecutiveBytes(receiveDataFromServer, firstByteOfNumOfAuthorityRRs);
					
					pointer += numberOfBytesInHeader;
	
					if (flagResponseCode == 0 && numberOfAnswerRecords == 0 && numberOfAuthorityRecords > 0) {
						advancePointerToAuthorityRData(receiveDataFromServer);
						/*Reached to first byte of authority RData */
						String nameServer = createAddressString(pointer, receiveDataFromServer);
						try {
							currentAddress = InetAddress.getByName(nameServer.toString());
						} catch (UnknownHostException e) {
							System.err.printf("Unknown host");
							System.exit(1);
						}
					} else {
						if (numberOfAnswerRecords > 0 || flagResponseCode != 0) {
							sendPacketToClient(receiveDataFromServer, isValidDomainName, serverSocket);
							if(clientSocket != null) {
								clientSocket.close();
							}
							
							break;
						}
					}
				}
			}
		}
		
		if(serverSocket != null) {
			serverSocket.close();
		}
	}
	
	private static HashSet<String> convertBlockListToHashSet(String pathOfTextFile){
		HashSet<String> blockList = new HashSet<String>();
		BufferedReader reader = null;
		String line = "";
		
		try {
			reader = new BufferedReader(new FileReader(pathOfTextFile));
		} catch (FileNotFoundException e) {
			System.err.printf("Incorrect path");
			System.exit(1);
		}
		
		try {
			while((line = reader.readLine())!=null) {
				blockList.add(line);
			}
		} catch (IOException e1) {
			System.err.printf("Can not iterate file, please try again");
			System.exit(1);
		}
		
		try {
			reader.close();
		} catch (IOException e) {
			System.err.printf("Can not close file");
			System.exit(1);
		}
		
		return blockList;
	}

	private static void initRootServersArray() {
		String rootServerHostNameTemplate = ".root-servers.net";
		char currentRootServerChar = 'a';
		String currentRootServerHostName = "";

		for (int i = 0; i < numberOfRootServers; i++) {
			currentRootServerHostName = currentRootServerChar + rootServerHostNameTemplate;
			try {
				rootServers[i] = InetAddress.getByName(currentRootServerHostName);
			} catch (UnknownHostException e) {
				System.err.printf("Unknown host name (root server)");
				System.exit(1);
			}
			currentRootServerChar = (char) (currentRootServerChar + 1);
		}
	}

	private static InetAddress getRandomRootServer() {
		int randomIndex = (int) (Math.random() * numberOfRootServers);

		return rootServers[randomIndex];
	}
	
	private static byte[] handlePacketFromClient(DatagramPacket receivePacketFromClient) {
		/*Save details of client in order to send the response later */
		hostIP = receivePacketFromClient.getAddress();
		hostPort = receivePacketFromClient.getPort();
		/**/
		byte[] receiveDataFromClient = receivePacketFromClient.getData();
		byte headerFlagsFirstHalf = receiveDataFromClient[firstByteOfFlagsInHeader];
		
		receiveDataFromClient[firstByteOfFlagsInHeader] = (byte) (headerFlagsFirstHalf & ((byte) 0b11111110)); //Turn off RD flag.
		receiveDataFromClient = Arrays.copyOfRange(receiveDataFromClient, 0, receivePacketFromClient.getLength()); //Resize
		
		return receiveDataFromClient;
	}
	
	private static void sendPacketToClient(byte[] dataToSendTheClient, boolean isValidDomainName, DatagramSocket serverSocket) {
		dataToSendTheClient = flagsFixingBeforeSendingResponse(dataToSendTheClient, isValidDomainName);
		DatagramPacket packetToClient = new DatagramPacket(dataToSendTheClient, dataToSendTheClient.length, hostIP, hostPort);
		
		try {
			serverSocket.send(packetToClient);
		} catch (IOException e) {
			System.err.printf("Problem with sending packet to the client");
			System.exit(1);
		}
	}
	
	private static byte[] flagsFixingBeforeSendingResponse(byte[] sendDataToClient, boolean isValidDomainName) {
		// Turn on RD bit :
		sendDataToClient[firstByteOfFlagsInHeader] = (byte) (sendDataToClient[firstByteOfFlagsInHeader] | (byte) 0b00000001);

		// Turn on Recursion Available bit:
		sendDataToClient[secondByteOfFlagsInHeader] = (byte) (sendDataToClient[secondByteOfFlagsInHeader] | (byte) 0b10000000);
		
		if(isValidDomainName == false) { //In case it's in the block list
			//Set RCODE = 3
			sendDataToClient[secondByteOfFlagsInHeader] = (byte) (sendDataToClient[secondByteOfFlagsInHeader] | (byte) 0b00000011);
			// Turn on QR bit:
			sendDataToClient[firstByteOfFlagsInHeader] = (byte) (sendDataToClient[firstByteOfFlagsInHeader] | (byte) 0b10000000);
		}
		else {
			// Turn off authority bit (The answer to the client is recursive):		
			sendDataToClient[firstByteOfFlagsInHeader] = (byte) (sendDataToClient[firstByteOfFlagsInHeader] & (byte) 0b11111011); 
		}

		return sendDataToClient;
	}

	private static byte getFlagResponseCode(byte[] receiveData) {
		byte headerFlagsSecondHalf = receiveData[secondByteOfFlagsInHeader];
		byte flagResponseCode = (byte) (headerFlagsSecondHalf & (byte) 0b00001111);

		return flagResponseCode;
	}

	private static char getTwoConsecutiveBytes(byte[] data, int indexOfFirstByte) {
		char twoBytesToReturn = 0;
		byte firstByte = data[indexOfFirstByte];
		byte secondByte = data[indexOfFirstByte + 1];
		
		twoBytesToReturn = (char) (twoBytesToReturn | firstByte << numOfBitsInByte);
		twoBytesToReturn = (char) (twoBytesToReturn | secondByte);

		return twoBytesToReturn;
	}
	
	private static void advancePointerToAuthorityRData (byte[] receiveDataFromServer) {
		/*The pointer is currently points to the first byte of questions section */
		byte currentByte;
		boolean isAuthorityNameHasPointer = false;
		
		//Skips the name in question section:
		while ((currentByte = receiveDataFromServer[pointer]) != 0) { 
			pointer++;
		}
		
		/*The pointer is currently points to the first byte of question QTYPE */
		pointer++; //Skips the zero octet
		pointer += 4; //2 bytes for QTYPE + 2 bytes for QCLASS
		/*The pointer is currently points to the first byte of authority section -> authority name  (answers=0) */
		
		
		while ((currentByte = receiveDataFromServer[pointer]) != 0) {
			if (currentByte <= (byte) (0b11000000)) { // Indicates this is a pointer (Compressed)
				pointer = pointer +2; //Skip the offset of authority name
				isAuthorityNameHasPointer = true;
				break;
			} else {
				pointer++;
			}
		} 
		/*The pointer is currently points to the last byte of authority NAME */
		
		if(isAuthorityNameHasPointer == false) {
			pointer++; //Skips the zero octet
		}
		
		pointer += 10; // 2 bytes for TYPE + 2 bytes for CLASS + 4 bytes for TTL + 2 byte of 2 for RDLength
	}
	private static String createAddressString(int relevantPointer, byte[] receivedData) {
		/*relevantPointer = points to the first byte of the name (numOfChars \ 0b11....) */
		StringBuilder address = new StringBuilder();
		byte numberOfCharactersTillTheNextDot;
		byte currentByte;
		int pointerForOffset;
		
		while ((currentByte = receivedData[relevantPointer]) != 0) {
			if (currentByte <= (byte) (0b11000000)) { // Indicates this is a pointer (Compressed)
				pointerForOffset = getOffset(currentByte, receivedData[relevantPointer+1]);
				relevantPointer = pointerForOffset;
			} else {
				numberOfCharactersTillTheNextDot = currentByte;
				for (int i = 0; i < numberOfCharactersTillTheNextDot; i++) {
					relevantPointer++;
					currentByte = receivedData[relevantPointer];
					address.append((char) currentByte);
				}

				address.append((char) dotInAscii); // Add dot to the end of the octet
				relevantPointer++;
			}
		}
		
		address.deleteCharAt(address.length() - 1); // Delete redundant dot at the end of the name server
		
		return address.toString();
	}
	
    private static int getOffset(byte firstByteOfOffset, byte secondByteOfOffset) {
    	int firstPartOfOffset = Byte.toUnsignedInt((byte) (firstByteOfOffset - (byte)0b11000000));
    	int secondPartOfOffset = Byte.toUnsignedInt(secondByteOfOffset);
        int offset = 0;
        offset = offset | (firstPartOfOffset << numOfBitsInByte);
        offset = offset | (secondPartOfOffset);
        
        return offset;
    }
}
