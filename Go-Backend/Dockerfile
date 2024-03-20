# Usamos una imagen de Go como base
FROM golang:1.21.6

# Establecemos el directorio de trabajo dentro del contenedor
WORKDIR /go/src/app

# Copiamos el contenido del directorio actual al directorio de trabajo del contenedor
COPY . .

# Construimos el ejecutable de la aplicación Go
RUN go build -o myapp .

# Exponemos el puerto 5000 en el contenedor
EXPOSE 5000

# Comando por defecto para ejecutar la aplicación cuando se inicie el contenedor
CMD ["./myapp"]


#docker build -t my-go-app .
#docker run -p 5000:5000 my-go-app
