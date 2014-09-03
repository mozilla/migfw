echo "Enter Filename without extension - "
read fname
gcc -g -o $fname $fname.c -liptc -lip4tc -lip6tc -ldl