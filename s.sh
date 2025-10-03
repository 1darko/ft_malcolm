#!/bin/bash

cc main.c
sudo valgrind --leak-check=full ./a.out 10.0.2.66 52:54:00:12:35:00 10.2.2.15 001122CC44BB
