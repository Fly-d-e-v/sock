#ifndef SOCKET_SOCK_H
#define SOCKET_SOCK_H

#include <iostream>

#ifdef __linux__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>

#include <unistd.h>
#include <string.h>

#elif _WIN32

// To remove depricated warning
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h>
#include <WS2tcpip.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")

#endif

#include <functional>

#define TCP IPPROTO_TCP
#define UDP IPPROTO_UDP

#define BLOCK true
#define NO_BLOCK false

#define SOCKET_FAILED -1
#define BIND_FAILED -1

#define MAX_BUFFER_LENGTH 512

namespace sock {

	/**
	 * \brief Socket class
	*/
	class Socket {
	public:
		/**
		 * \brief Constructor
		*/
		Socket() { initialized = false; };

	public:
#ifdef __linux__
		int socket;
#elif _WIN32
		SOCKET socket;
#endif

		bool initialized;
		sockaddr_in * si;
		int protocol;
	};

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * \brief Create a socket
	 * \param protocol - Socket protocol (TCP, UDP)
	 * \param does_block - NO_BLOCK or BLOCK
	*/
	inline Socket* CreateSocket(int protocol, bool does_block) {
		Socket* new_socket = new Socket();

		new_socket->protocol = protocol;

		int type;

		if (protocol == UDP)
			type = SOCK_DGRAM;
		else if (protocol == TCP)
			type = SOCK_STREAM;

#ifdef __linux__
		new_socket->socket = socket(AF_INET, type, new_socket->protocol);

		if (new_socket->socket < 0) {
			std::cout << "Failed to create socket (" << errno << ")\n";
			return nullptr;
		}

		// Set to non blocking if NO_BLOCK
		if (!does_block) {
			int flags;
			flags = fcntl(new_socket->socket, F_GETFL, 0);
			flags |= O_NONBLOCK;


			if (fcntl(new_socket->socket, F_SETFL, flags) < 0) {
				std::cout << "Failed to flag socket (" << errno << ")\n";
			}

		}

#elif _WIN32
		WSADATA wsa_data;

		int startup_return = WSAStartup(MAKEWORD(2, 2), &wsa_data);

		if (startup_return != 0) {
			std::cout << "Cannot initialize WinsSock\n";
			WSACleanup();
		}

		new_socket->socket = socket(AF_INET, type, new_socket->protocol);

		if (new_socket->socket == INVALID_SOCKET) {
			std::cout << "Failed to create socket (" << WSAGetLastError() << ")\n";
			return nullptr;
		}

#endif

		new_socket->initialized = true;

		return new_socket;
	}

	/**
	 * \brief Bind a socket for server hosting
	 * \param in_socket - Socket to be bound
	 * \param port - Port to bind on
	*/
	inline int Bind(Socket* in_socket, uint16_t port) {
		if (!in_socket->initialized)
			return -2;

		in_socket->si = new sockaddr_in;
		in_socket->si->sin_family = AF_INET;
		in_socket->si->sin_port = port;
		in_socket->si->sin_addr.s_addr = htonl(INADDR_ANY);

#ifdef __linux__
		int	bind_return = bind(in_socket->socket, (sockaddr*)in_socket->si, sizeof(*in_socket->si));
		
		if (bind_return < 0) {
			std::cout << "Failed to bind socket (" << errno << ")\n";
			return bind_return;
		}

		if (in_socket->protocol == TCP) {
			int l = listen(in_socket->socket, 5);

			if (l < 0) {
				std::cout << "Failed to listen (" << errno << ")\n";
				return bind_return;
			}
		}

		std::cout << "Socket bound (" << in_socket->si->sin_port << ")\n";

		return bind_return;

#elif _WIN32
		int bind_return = bind(in_socket->socket, (sockaddr*)in_socket->si, sizeof(*in_socket->si));

		if (bind_return == SOCKET_ERROR)
			std::cout << "Failed to bind socket (" << WSAGetLastError() << ")\n";

		if (in_socket->protocol == TCP)
		{
			int l = listen(in_socket->socket, 5);

			if (l < 0) {
				std::cout << "Failed to listen (" << WSAGetLastError() << ")\n";
				return bind_return;
			}
		}

		std::cout << "Socket bound (" << in_socket->si->sin_port << ")\n";

		return bind_return;

#endif
	}

	/**
	 * \brief Accept incoming connection (TCP only)
	 * \param open_socket - The bound socket to accept on
	 * \param new_socket - Connected socket
	 * \param does_block - NO_BLOCK or BLOCK
	*/
	inline bool Accept(Socket* const open_socket, Socket* new_socket, bool does_block) {

		sockaddr_in client_addr;
		socklen_t client_length = sizeof(client_addr);

#ifdef __linux__
		int client_socket = -1;

		int flags = 0;

		if (!does_block)
			flags = SOCK_NONBLOCK;

		client_socket = accept4(open_socket->socket, (sockaddr*)&client_addr, &client_length, flags);

		if (client_socket < 0) {
			return false;
		}

#elif _WIN32
		SOCKET client_socket;

		client_socket = accept(open_socket->socket, (sockaddr*)&client_addr, &client_length);

		std::cout << "Client Connected: " << client_socket << std::endl;

		if (client_socket < 0) {
			return false;
		}

#endif
		Socket cr_s;

		cr_s.socket = client_socket;
		cr_s.si = new sockaddr_in(client_addr);
		cr_s.initialized = true;
		cr_s.protocol = TCP;

		*new_socket = cr_s;

		return true;
	}

	/**
	 * \brief Receive packet
	 * \param in_socket - Receiving socket
	 * \param buffer - Pointer to buffer to fill
	 * \param does_block - NO_BLOCK or BLOCK
	*/
	inline int Receive(Socket* const in_socket, char* buffer, bool does_block) {
		if (!in_socket) {
			std::cout << "Trying to receive on nullptr socket\n";
			return 0;
		}

#ifdef __linux__
		int flags = 0;

		if (!does_block)
			flags = MSG_DONTWAIT;

		int receive_return = recv(in_socket->socket, buffer, MAX_BUFFER_LENGTH, flags);

		if (receive_return == 0) {
			std::cout << "Trying to receive on closed socket\n";
			return 0;
		}

		if (receive_return < 0)
			return receive_return;

#elif _WIN32
		if (!does_block) {
			unsigned long bytes_to_read;
			ioctlsocket(in_socket->socket, FIONREAD, &bytes_to_read);

			if (bytes_to_read < 1)
				return -1;
		}

		int receive_return = recv(in_socket->socket, buffer, MAX_BUFFER_LENGTH, 0);

		if (receive_return == 0) {
			std::cout << "Trying to receive on closed socket\n";
			return 0;
		}

		if (receive_return < 0)
			return receive_return;
#endif

		uint16_t header = (uint16_t)*buffer;

		if (header > 0)
			return header;

		return -1;
	}

	/**
	 * \brief Connect to a socket (TCP only)
	 * \param to_socket - Socket to use
	 * \param ip - IPv4 to connect to
	 * \param port - Port to connect to
	*/
	inline int Connect(Socket* to_socket, const char* ip, uint16_t port) {
		if (!to_socket->initialized || to_socket->protocol != TCP)
			return -2;

		to_socket->si = new sockaddr_in;
		to_socket->si->sin_family = AF_INET;
		to_socket->si->sin_port = port;

		// Depricated on Windows
		to_socket->si->sin_addr.s_addr = inet_addr(ip);

#ifdef __linux__
		int connect_return = connect(to_socket->socket, (sockaddr*)to_socket->si, sizeof(*to_socket->si));

		if (connect_return < 0)
			std::cout << "Failed to connect (" << errno << ")\n";

		return connect_return;

#elif _WIN32
		int connect_return = connect(to_socket->socket, (sockaddr*)to_socket->si, sizeof(*to_socket->si));

		if (connect_return < 0)
			std::cout << "Failed to connect (" << WSAGetLastError() << ")\n";

		return connect_return;
#endif
	}

	/**
	 * \brief Set socket adress
	 * \param set_socket - Socket to use
	 * \param ip - IPv4 to connect to
	 * \param port - Port to connect to
	*/
	inline void Set(Socket* set_socket, const char* ip, uint16_t port) {
		set_socket->si = new sockaddr_in;
		set_socket->si->sin_family = AF_INET;
		set_socket->si->sin_port = port;
		set_socket->si->sin_addr.s_addr = inet_addr(ip);
	}

	/**
	 * \brief Send a packet
	 * \param to_socket - The socket to send on
	 * \param buffer - Buffer to send
	 * \param bytes - Size of buffer in bytes
	*/
	inline int Send(Socket* const to_socket, char* buffer, uint16_t bytes) {
		if (bytes > MAX_BUFFER_LENGTH)
			return -1;

		if (!to_socket) {
			std::cout << "Trying to send to nullptr socket\n";
			return -1;
		}

		int send_return = -1;

#ifdef __linux__
		send_return = sendto(to_socket->socket, buffer, bytes, MSG_DONTWAIT, (sockaddr*)to_socket->si, sizeof(*to_socket->si));

		if (send_return < 0) {
			std::cout << "Error sending buffer (" << errno << ")\n";
			return send_return;
		}

#elif _WIN32
		send_return = sendto(to_socket->socket, buffer, bytes, 0, (sockaddr*)to_socket->si, sizeof(*to_socket->si));

		if (send_return == SOCKET_ERROR) {
			std::cout << "Error sending buffer (" << WSAGetLastError() << ")\n";
			return send_return;
		}

#endif

		return send_return;
	}

	/**
	 * \brief Close a socket. Not closing sockets after completion can cause future binding errors
	 * \param in_socket - Socket to close
	*/
	inline void Close(Socket* const in_socket) {
#ifdef __linux__
		close(in_socket->socket);

#elif _WIN32
		closesocket(in_socket->socket);

#endif
	}

	inline int ReceiveFrom(Socket* const in_socket, sockaddr_in* si, char* buffer, bool does_block) {
		if (!in_socket) {
			std::cout << "Trying to receive on nullptr socket\n";
			return 0;
		}

#ifdef __linux__
		int flags = 0;

		if (!does_block)
			flags = MSG_DONTWAIT;

		socklen_t len = sizeof(*si);
		int receive_return = recvfrom(in_socket->socket, buffer, MAX_BUFFER_LENGTH, flags, (sockaddr*)si, &len);

		if (receive_return == 0) {
			std::cout << "Trying to receive on closed socket\n";
			return 0;
		}

		if (receive_return < 0)
			return receive_return;
#endif

#ifdef _WIN32

		socklen_t len = sizeof(*si);
		int receive_return = recvfrom(in_socket->socket, buffer, MAX_BUFFER_LENGTH, 0, (sockaddr*)si, &len);

		if (receive_return == SOCKET_ERROR) {
			std::cout << "Trying to receive on closed socket\n";
			return 0;
		}

		if (receive_return < 0)
			return receive_return;
#endif
		uint16_t header = (uint16_t)*buffer;

		if (header > 0)
			return header;

		return -1;
	}

	inline int SendTo(Socket* const to_socket, sockaddr_in* si, char* buffer, uint16_t bytes) {
		if (bytes > MAX_BUFFER_LENGTH)
			return -1;

		if (!to_socket) {
			std::cout << "Trying to send to nullptr socket\n";
			return -1;
		}

		int send_return = -1;

#ifdef __linux__
		send_return = sendto(to_socket->socket, buffer, bytes, MSG_DONTWAIT, (sockaddr*)si, sizeof(*si));

		if (send_return < 0) {
			std::cout << "Error sending buffer (" << errno << ")\n";
			return send_return;
		}
#endif

#ifdef _WIN32
		send_return = sendto(to_socket->socket, buffer, bytes, 0, (sockaddr*)si, sizeof(*si));

		if (send_return < 0) {
			std::cout << "Error sending buffer (" << errno << ")\n";
			return send_return;
		}
#endif

		return send_return;
	}
}

#endif