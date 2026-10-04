#include <cstdio>

SocketClient client;
void startDaemon();
int startClient(const char *libName);
bool sendLibConfig(const char *libName);
bool isConnected();
void stopClient();
bool initServer();
bool stopServer();

enum Mode {
    InitMode = 1,
    HackMode = 2,
    StopMode = 3,
    ConfigMode = 4, // kirim konfigurasi (nama lib target) ke server
    EspMode = 99,
};

struct Request {
    int Mode;
    bool isOn;
    int Value;
    int screenWidth;
    int screenHeight;
};

// Pesan konfigurasi client -> server. Dikirim sekali setelah InitMode.
struct ConfigRequest {
    int Mode;          // = Mode::ConfigMode
    char libName[128]; // nama lib target, mis. "libil2cpp.so"
};




#define maxplayerCount 54

struct PlayerData {
    char PlayerName[64];
    float Health;
    float Distance2;
    bool get_IsDieing;
    bool isBot;
    Vector3 CloseEnemyHeadLocation;
    Vector3 HeadLocation;
    Vector3 ToeLocation;
    Vector2 RShoulder;
    Vector3 LShoulder;
    Vector3 Toe;
    Vector3 Hip;
    Vector3 Head;
    int x;
    int y;
    int z;
    int id;
    int h;
    char debug[60];
};

struct Response {
    bool Success;
    int PlayerCount;
    PlayerData Players[maxplayerCount];
};




int startClient(const char *libName){
    client = SocketClient();
    if(!client.Create()){ return -1; }
    if(!client.Connect()){ return -1; }
    if(!initServer()){ return -1; }
    // Beritahu server nama lib target (dari Settings, atau default)
    sendLibConfig(libName);
    return 0;
}

// Kirim nama lib target ke server. Best-effort: kegagalan tidak menggagalkan
// konek karena server punya default ("libil2cpp.so").
bool sendLibConfig(const char *libName) {
    ConfigRequest cfg{};
    cfg.Mode = Mode::ConfigMode;
    snprintf(cfg.libName, sizeof(cfg.libName), "%s",
             (libName && libName[0]) ? libName : "libil2cpp.so");
    int code = client.sendX((void*) &cfg, sizeof(cfg));
    if (code > 0) {
        Response response{};
        size_t length = client.receive((void*) &response);
        if (length > 0) {
            return response.Success;
        }
    }
    return false;
}

bool isConnected(){
   return client.connected;
    
}

void stopClient() {
    if(client.created && isConnected()){
        stopServer();
        client.Close();
    }
}

bool initServer() {
    Request request{Mode::InitMode, true, 0};
    int code = client.sendX((void*) &request, sizeof(request));
    if(code > 0) {
        Response response{};
        size_t length = client.receive((void*) &response);
        if(length > 0) {
            return response.Success;
        }
    }
    return false;
}

bool stopServer() {
    Request request{Mode::StopMode};
    int code = client.sendX((void*) &request, sizeof(request));
    if(code > 0) {
        Response response{};
        size_t length = client.receive((void*) &response);
        if(length > 0) {
            return response.Success;
        }
    }
    return false;
}

void Send(int32_t number, bool ftr) {
    Request request{number, ftr};
    int code = client.sendX((void*) &request, sizeof(request));
    if (code > 0) {
        Response response{};
        size_t length = client.receive((void*) &response);
        if (length > 0) {
             ;
        }
    }
}
void Send(int32_t number, int Value) {
    Request request{number, true, Value};
    int code = client.sendX((void*) &request, sizeof(request));
    if (code > 0) {
        Response response{};
        size_t length = client.receive((void*) &response);
        if (length > 0) {
             ;
        }
    }
}
Response getData(int screenWidth, int screenHeight){
    Request request{Mode::EspMode, screenWidth, screenHeight};
    int code = client.sendX((void*) &request, sizeof(request));
    if(code > 0){
        Response response{};
        size_t length = client.receive((void*) &response);
        if(length > 0){
            return response;
        }
    }
    Response response{false, 0};
    return response;
}
bool isValidPlayer(PlayerData data) {
    return (data.HeadLocation != Vector3::Zero());
}
bool isValidCloseEnemy(PlayerData data) {
    return (data.CloseEnemyHeadLocation != Vector3::Zero());
}
