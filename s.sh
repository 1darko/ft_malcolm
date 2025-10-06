#!/bin/bash

cc main.c
sudo valgrind --leak-check=full ./a.out 10.0.2.5 08:00:27:E7:EB:9F 10.0.2.200 001122CC44BB
