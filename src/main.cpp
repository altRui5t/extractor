


/*
Как и обещали прикладываем тестовое задание. Если возникнут вопросы то обязательно задавайте 

Описание
PCAP-файл содержит записанный трафик получения изображения по протоколу http
https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/http_with_jpegs.cap.gz

На вход приложения передаются
 1. путь к pcap-файлу
 2. ip-адрес отправителя
 3. tcp-порт отправителя
 4. ip-адрес получателя
 5. tcp-порт получателя

На выходе приложения должен быть сформирован файл с изображением image.out
Успешным будет считаться решение с корректным (без артефактов) изображением на выходе приложения.

Ограничения
* Необходимо писать на языке C++ для ОС Ubuntu 22 и компилятора gcc
* Оформить проект в виде make/cmake файла для сборки
* Использовать библиотеку libpcap для парсинга файла
* Использовать системные заголовочные файлы с ethernet, ip и tcp структурами
* Проверять контрольные суммы не нужно
* В одном TCP-потоке содержится только одно изображение

*/

#include <iostream>
#include <getopt.h>
#include <map>

#include "capReader.h"

int main(int argc, char **argv){


    const struct option longopts[] =
    {
        {"src",   required_argument,  0, 's'},
        {"srcp",  required_argument,  0, 'p'},
        {"dst",   required_argument,  0, 'd'},
        {"dstp",  required_argument,  0, 'b'},
        {"file",  required_argument,  0, 'f'},
        {0,0,0,0},
    };
    int index;
    std::map<std::string, std::string> params {{"src", ""},{"dst", ""},{"srcp", ""},{"dstp", ""},{"filepath", ""}};

    for(;;)
    {
        switch(getopt_long(argc, argv, "s:p:d:b:f:", longopts, &index )) 
        {
            case 's':
                params["src"] = optarg;
                continue;

            case 'p':
                params["srcp"] = optarg;
                continue;

            case 'd':
                params["dst"] = optarg;
                continue;

            case 'b':
                params["dstp"] = optarg;
                continue;
            
            case 'f':
                params["filepath"] = optarg;
                continue;

            default :
                std::cerr << "extractor --file file.pcap --src 0.0.0.0 --srcp 65500 --dst 0.0.0.0 --dstp 65500" << std::endl;
                return 1;
            case -1:
                break;
        }
        break;
    }
    
    for (const auto& [key,value]: params)
        if (value.empty()){
            std::cerr << "empty value for param: " << key << std::endl;
            std::cerr << "extractor --file file.pcap --src 0.0.0.0 --srcp 65500 --dst 0.0.0.0 --dstp 65500" << std::endl;
            return 2;
        }

    CapReader reader(params["filepath"]);

    bool res = reader.SaveImage(params["src"],params["srcp"],params["dst"],params["dstp"]);

    if (res)
        std::cout << "Image extraction complete" << std::endl;
    else
        std::cout << "Image extraction failed" << std::endl;
    
}