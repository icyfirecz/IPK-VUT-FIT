import sys
import socket as sock
import json

"""
    Function creates HTTP request for the weather API.
    Function returns exact HTTP request.
"""
def create_HTTP_request(key, city):
    request = "GET https://api.openweathermap.org/data/2.5/weather?q=" + city
    request += "&APPID=" + key
    request += "&units=metric"
    request += " HTTP/1.1\r\n" + "Host: api.openweathermap.org\r\n"
    request += "Connection: close\r\n\r\n"

    return request

"""
    Function checks if the HTTP transaction was successful.
"""
def check_HTTP_reponse(response):
    if response != "HTTP/1.1 200 OK\r":
        sys.exit("Error, cannot reach communication with API.")

"""
    Function creates socket and asks the API for JSON with data.
    Function returns the JSON data and HTTP request result.
"""
def request_json(key, city):
    host = 'api.openweathermap.org'
    port = 80
    request = create_HTTP_request(key, city)

    try:
        socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        socket.connect((host,port))

        socket.sendall(request.encode())
        result = socket.recv(4096)

    except Exception:
        sys.exit("Error, creating or connecting socket to API.")

    result = result.decode()

    result = result.split("\n")
    
    return result[11], result[0]

"""
    Function writes the weather from the JSON data.
"""
def show_weather(apiJson):
    try:
        print(apiJson["name"],",",apiJson["sys"]["country"])
    except Exception:
        print("- , -")

    try:
        print(apiJson["weather"][0]["description"])
    except Exception:
        print("-")
    
    try:
        print("temp:", apiJson["main"]["temp"], "°C")
    except Exception:
        print("temp: - °C")
    
    try:
        print("humidity:", apiJson["main"]["humidity"], "%")
    except Exception:
        print("humidity: - %")
    
    try:
        print("pressure:", apiJson["main"]["pressure"], "hpa")
    except Exception:
        print("pressure: - hpa")

    try:
        print("wind:", (3600/1000)*(apiJson["wind"]["speed"]), "km/h")
    except Exception:
        print("wind: - km/h")
    
    try:
        print("wind degree:", apiJson["wind"]["deg"])
    except Exception:
        print("wind degree: - ") 

if len(sys.argv) != 3:
    sys.exit("Error, wrong number of parameters.")

apiKey = sys.argv[1]
apiCity = sys.argv[2]

apiJson, apiHTTP = request_json(apiKey, apiCity)

check_HTTP_reponse(apiHTTP)

apiJson = json.loads(apiJson)

#debug json
#print(apiJson)

show_weather(apiJson)