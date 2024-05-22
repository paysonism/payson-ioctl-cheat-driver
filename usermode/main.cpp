#include <iostream>
#include "driver.h"

using namespace std;


void main() 
{
	SetConsoleTitleA("Payson IOCTL - github.com/paysonism - Usermode Example");
	if (!mem::find_driver()) {
		system("color 2");
		cout << "\n Driver isn't loaded!\n";
	}
	mem::process_id = mem::find_process("explorer.exe");

	virtualaddy = mem::find_image();

	cout << "File Explorer Base Address -> " << virtualaddy << "\n";

	cin.get();

	//FortniteClient-Win64-Shipping.exe
}