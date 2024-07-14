#include "header.h"

int TCPConThrdNum;
pthread_mutex_t TCPConPrintlocker = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t TCPConScanlocker = PTHREAD_MUTEX_INITIALIZER;

void* Thread_TCPconnectHost(void* param) {
    /*变量定义*/
    //获得目标主机的IP地址和扫描端口号
    struct TCPConHostThrParam* p = (struct TCPConHostThrParam*)param;
    std::string hostIP = p->HostIP;
    unsigned hostPort = p->HostPort;
    //创建流套接字
    int conSock = socket(AF_INET, SOCK_STREAM, 0);
    if (conSock < 0) {
        pthread_mutex_lock(&TCPConPrintlocker);

    }

    //设置连接主机地址
    struct sockaddr_in hostAddr;
    memset(&hostAddr, 0, sizeof(hostAddr));
    hostAddr.sin_family = AF_INET;
    hostAddr.sin_addr.s_addr = inet_addr(&hostIP[0]);
    hostAddr.sin_port = htons(hostPort);
    //connect目标主机
    int ret = connect(conSock, (struct sockaddr*)&hostAddr, sizeof(hostAddr));
    if (ret < 0) {
        pthread_mutex_lock(&TCPConPrintlocker);
        std::cout << "TCP connect scan: " << hostIP << ":" << hostPort << " is closed" << std::endl;
        pthread_mutex_unlock(&TCPConPrintlocker);
    }
    else {
        pthread_mutex_lock(&TCPConPrintlocker);
        std::cout << "TCP connect scan: " << hostIP << ":" << hostPort << " is open" << std::endl;
        pthread_mutex_unlock(&TCPConPrintlocker);
    }
    delete p;
    close(conSock); //关闭套接字
    //子线程数减1
    pthread_mutex_lock(&TCPConScanlocker);
    TCPConThrdNum--;
    pthread_mutex_unlock(&TCPConScanlocker);
} // TCP connect 扫描

void* Thread_TCPconnectScan(void* param)
{
    /*变量定义*/
    //获得扫描的目标主机IP，启始端口，终止端口
    struct TCPConThrParam* p = (struct TCPConThrParam*)param;
    std::string hostIP = p->HostIP;
    unsigned beginPort = p->BeginPort;
    unsigned endPort = p->EndPort;
    TCPConThrdNum = 0; //将线程数设为0
    //开始从起始端口到终止端口循环扫描目标主机的端口
    pthread_t subThreadID;
    pthread_attr_t attr;
    for (unsigned tempPort = beginPort; tempPort <= endPort; tempPort++)
    {
        //设置子线程参数
        TCPConHostThrParam* pConHostParam = new TCPConHostThrParam;
        pConHostParam->HostIP = hostIP;
        pConHostParam->HostPort = tempPort;
        //将子线程设为分离状态
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        //创建connect目标主机指定的端口子线程
        int ret = pthread_create(&subThreadID, &attr, Thread_TCPconnectHost, pConHostParam);
        if (ret == -1) {
            std::cout << "Create TCP connect scan thread error!" << std::endl;
        }
        //线程数加1
        pthread_mutex_lock(&TCPConScanlocker);
        TCPConThrdNum++;
        pthread_mutex_unlock(&TCPConScanlocker);
        //如果子线程数大于100，暂时休眠
        while (TCPConThrdNum > 100) {
            sleep(3);
        }
    }
    //等待子线程数为0，返回
    while (TCPConThrdNum != 0) {
        sleep(1);
    }
    pthread_exit(NULL);
}
