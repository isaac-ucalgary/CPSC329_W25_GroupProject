cd ./src || exit

zip -r ../out/cryptographic_tools_app.zip ./* -x rsa/.zig-cache/**\*

cd ../out || exit

python3 -m zipapp cryptographic_tools_app.zip -o cryptographic_tools_app
