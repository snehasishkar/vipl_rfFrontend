################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/fifo_read_write.cpp \
../src/main.cpp \
../src/vipl_printf.cpp \
../src/vipl_wifi_demod.cpp \
../src/viplrfinterface.cpp 

OBJS += \
./src/fifo_read_write.o \
./src/main.o \
./src/vipl_printf.o \
./src/vipl_wifi_demod.o \
./src/viplrfinterface.o 

CPP_DEPS += \
./src/fifo_read_write.d \
./src/main.d \
./src/vipl_printf.d \
./src/vipl_wifi_demod.d \
./src/viplrfinterface.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -I/usr/include/libnl3 -O0 -g3 -Wall -c -fmessage-length=0 -fpermissive -std=c++11 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


