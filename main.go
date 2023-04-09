package main

import (
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const (			 //baza bilan bog'lanish uchun
	host     = "containers-us-west-87.railway.app" //host
	port     = 7572                                //port
	user     = "postgres"                          //foydalanuvchi
	password = "4aMQQl5p9qnUD52lJaaL"              //parol
	dbname   = "railway"                           //baza nomi
)

type User struct { //foydalanuvchi
	ID          int       `json:"id"`           //id											1
	Username    string    `json:"username"`     //login											2
	Email       string    `json:"email"`        //email											3
	Password    string    `json:"password"`     //parol											4
	Name        string    `json:"name"`         //ismi											5
	Surname     string    `json:"surname"`      //familiyasi									6
	Age         int       `json:"age"`          //yoshi											7
	Phone       string    `json:"phone"`        //telefon raqami								8
	Promocode   string    `json:"promocode"`    //promokod										9
	Status      string    `json:"status"`       //holati										10
	Roles       string    `json:"roles"`        //roli											11
	City        string    `json:"city"`         //shahri										12
	CreatedAt   time.Time `json:"created_at"`   //yaratilgan vaqti								13
	Token       string    `json:"token"`        //tokeni										14
	Blocked     bool      `json:"blocked"`      //bloklanganmi									15
	WarehouseID int       `json:"warehouse_id"` //ombor id										16
}

type Warehouse struct { //ombor
	ID        int       `json:"id"`        		//id											1
	Name      string    `json:"name"`      		//nomi											2
	City      string    `json:"city"`     		//shahri										3
	CreatedAt time.Time `json:"created_at"`		//yaratilgan vaqti								4
	CreatedBy string    `json:"created_by"` 	//yaratgan foydalanuvchi						5
	Status    string    `json:"status"`    		//holati										6
	Blocked   bool      `json:"blocked"`   		//bloklanganmi									7
}

type Category struct { //kategoriyalar
	ID          int       `json:"id"`           //id											1
	CatID       string    `json:"cat_id"`       //kategoriyasi									2
	Name        string    `json:"name"`         //nomi											3
	Description string    `json:"description"`  //eslatma										4
	CreatedAt   time.Time `json:"created_at"`   //yaratilgan vaqti								5
	CreatedBy   string    `json:"created_by"`   //yaratgan foydalanuvchi						6
	Status      string    `json:"status"`       //holati										7
	WarehouseID int       `json:"warehouse_id"` //qaysi omborda									8
}

type Product struct { //mahsulot
	ID          int       `json:"id"`           //id 											1
	CatID       string    `json:"cat_id"`       //kategoriyasi									2
	ProductID   string    `json:"product_id"`   //mahsulot id									3
	WarehouseID float64   `json:"warehouse_id"` //qaysi omborda									4
	Name        string    `json:"name"`         //nomi											5
	Description string    `json:"description"`  //eslatma										6
	Picture     string    `json:"picture"`      //rasmi											7
	Cauntry     string    `json:"cauntry"`      //mamlakati										8
	Code        float64   `json:"code"`         //kodi											9
	Price       float64   `json:"price"`        //sotish narxi									10
	Benicifits  float64   `json:"benicifits"`   //foydasi										11
	Discount    float64   `json:"discount"`     //skidka										12
	Currency    string    `json:"currency"`     //valyuta										13
	Quantity    float64   `json:"quantity"`     //miqdori										14
	Guarantee   float64   `json:"guarantee"`    //garantiya										15
	Measurement string    `json:"measurement"`  //o'lchov birligi - soni						16
	Parts       string    `json:"parts"`        //qismi - partiya								17
	Barcode     string    `json:"barcode"`      //barkod										18
	Brand       string    `json:"brand"`        //brendi										19
	Type        string    `json:"type"`         //turi - tipi									20
	CreatedAt   time.Time `json:"created_at"`   //yaratilgan vaqti								21
	CreatedBy   string    `json:"created_by"`   //yaratgan foydalanuvchi						22
	Status      string    `json:"status"`       //holati										23
}

type Order struct { //buyurtmalar
	ID          int       `json:"id"`           //id											1
	OrderID     string    `json:"order_id"`     //buyurtma id									2
	ProductID   string    `json:"product_id"`   //mahsulot id									3
	WarehouseID float64   `json:"warehouse_id"` //qaysi omborda									4
	Quantity    float64   `json:"quantity"`     //miqdori										5
	Price       float64   `json:"price"`        //narxi											6
	Currency    string    `json:"currency"`     //valyuta										7
	Discount    float64   `json:"discount"`     //skidka			
	Country     string    `json:"country"`      //mamlakati										9
	Code 	  	float64   `json:"code"`         //kodi											10
	Barcode     string    `json:"barcode"`      //barkod										11
	Brand       string    `json:"brand"`        //brendi										12
	Type        string    `json:"type"`         //turi - tipi									13
	CreatedAt   time.Time `json:"created_at"`   //yaratilgan vaqti								14
	CreatedBy   string    `json:"created_by"`   //yaratgan foydalanuvchi						15
	Status      string    `json:"status"`       //holati										16
}

type OrderHistory struct { //buyurtma tarixi
	ID          int       `json:"id"`           //id											1
	OrderID     string    `json:"order_id"`     //buyurtma id									2
	ProductID   string    `json:"product_id"`   //mahsulot id									3
	WarehouseID float64   `json:"warehouse_id"` //qaysi omborda									4
	Quantity    float64   `json:"quantity"`     //miqdori										5
	Price       float64   `json:"price"`        //narxi											6
	Currency    string    `json:"currency"`     //valyuta										7
	Discount    float64   `json:"discount"`     //skidka
	Country     string    `json:"country"`      //mamlakati										9
	Code 	  	float64   `json:"code"`         //kodi											10
	Barcode     string    `json:"barcode"`      //barkod										11
	Brand       string    `json:"brand"`        //brendi										12
	Type        string    `json:"type"`         //turi - tipi									13
	CreatedAt   time.Time `json:"created_at"`   //yaratilgan vaqti								14
	CreatedBy   string    `json:"created_by"`   //yaratgan foydalanuvchi						15
	Status      string    `json:"status"`       //holati										16
}

type ProductHistory struct { //mahsulot tarixi
	ID          int       `json:"id"`           //id 											1
	CatID       string    `json:"cat_id"`       //kategoriyasi									2
	ProductID   string    `json:"product_id"`   //mahsulot id									3
	WarehouseID float64   `json:"warehouse_id"` //qaysi omborda									4
	Name        string    `json:"name"`         //nomi											5
	Description string    `json:"description"`  //eslatma										6
	Picture     string    `json:"picture"`      //rasmi											7
	Cauntry     string    `json:"cauntry"`      //mamlakati										8
	Code        float64   `json:"code"`         //kodi											9
	Price       float64   `json:"price"`        //sotish narxi									10
	Benicifits  float64   `json:"benicifits"`   //foydasi										11
	Discount    float64   `json:"discount"`     //skidka										12
	Currency    string    `json:"currency"`     //valyuta										13
	Quantity    float64   `json:"quantity"`     //miqdori										14
	Guarantee   float64   `json:"guarantee"`    //garantiya										15
	Measurement string    `json:"measurement"`  //o'lchov birligi - soni						16
	Parts       string    `json:"parts"`        //qismi - partiya								17
	Barcode     string    `json:"barcode"`      //barkod										18
	Brand       string    `json:"brand"`        //brendi										19
	Type        string    `json:"type"`         //turi - tipi									20
	CreatedAt   time.Time `json:"created_at"`   //yaratilgan vaqti								21
	CreatedBy   string    `json:"created_by"`   //yaratgan foydalanuvchi						22
	Status      string    `json:"status"`       //holati										23
}

//hisobotlar jami yuklar kirishi va chiqishi foydalar va zararlari 
type Report struct { //hisobotlar
	ID          int       `json:"id"`           //id											1
	ReportID    string    `json:"report_id"`    //hisobot id									2
	ProductID   string    `json:"product_id"`   //mahsulot id									3
	WarehouseID float64   `json:"warehouse_id"` //qaysi omborda									4
	Name        string    `json:"name"`         //nomi											5
	Description string    `json:"description"`  //eslatma										6
	Picture     string    `json:"picture"`      //rasmi											7
	Cauntry     string    `json:"cauntry"`      //mamlakati										8
	Code        float64   `json:"code"`         //kodi											9
	Price       float64   `json:"price"`        //sotish narxi									10
	Benicifits  float64   `json:"benicifits"`   //foydasi										11
	Discount    float64   `json:"discount"`     //skidka										12
	Currency    string    `json:"currency"`     //valyuta										13
	Quantity    float64   `json:"quantity"`     //miqdori										14
	Guarantee   float64   `json:"guarantee"`    //garantiya										15
	Measurement string    `json:"measurement"`  //o'lchov birligi - soni						16
	Parts       string    `json:"parts"`        //qismi - partiya								17
	Barcode     string    `json:"barcode"`      //barkod										18
	Brand       string    `json:"brand"`        //brendi										19
	Type        string    `json:"type"`         //turi - tipi									20
	CreatedAt   time.Time `json:"created_at"`   //yaratilgan vaqti								21
	CreatedBy   string    `json:"created_by"`   //yaratgan foydalanuvchi						22
	Status      string    `json:"status"`       //holati										23
}

func generateUserId() string { //yangi shifrlangan id yaratish
	rand.Seed(time.Now().UnixNano())                                                  //random raqam yaratish
	chars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") //harflar
	length := 32                                                                      //uzunligi
	b := make([]rune, length)                                                         //uzunlikdagi massiv
	for i := range b {                                                                //massivni to'ldirish
		b[i] = chars[rand.Intn(len(chars))] 								   		  //harflardan random tanlash
	}
	return string(b) 																  //stringga o'tkazish
}

func passwordHash(password string) string {                  						  //parolni shifrlash
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10) 					  //parolni shifrlash
	if err != nil {
		fmt.Println(err)
	}
	return string(hash)
}

func checkPasswordHash(password, hash string) bool { 								  //parolni tekshirish
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) 			  //parolni tekshirish
	return err == nil                                                    			  //agar xato bo'lmasa true qaytaradi
}

func generateToken(username string, password string, roles string) (string, error) {  //token yaratish
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{ //token yaratish
		"username":   username,
		"password":   password,
		"created_at": time.Now(),
		"roles":      roles,
	})
	tokenString, err := token.SignedString([]byte("secret")) //tokenni shifrlash
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func main() {
	r := gin.Default()
	r.POST("/register", register)         //Ro'yxatdan o'tish
	r.POST("/login", login)               //Kirish
	r.POST("/logout", logout)             //Chiqish
	r.POST("/addWarehouse", addWarehouse) //Ombor qo'shish
	r.POST("/addCategory", addCategory)   //Kategoriya qo'shish
	r.Run()                               //Serverni ishga tushirish
}

func connectDB() *sql.DB { //Dastur bilan bazaga ulanish
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+"password=%s dbname=%s sslmode=disable", host, port, user, password, dbname) //bazaga ulanish uchun ma'lumotlar
	db, err := sql.Open("postgres", psqlInfo)                                                                                       //bazaga ulanish
	if err != nil {
		panic(err)
	}
	err = db.Ping() //bazaga ulanishni tekshirish
	if err != nil {
		panic(err)
	}
	return db //bazaga ulanishni qaytarish
}

func register(c *gin.Context) { 									 //Ro'yxatdan o'tish
	var user User            										 //user modeli
	err := c.BindJSON(&user)  									 	 //jsonni user modeliga o'tkazish
	if err != nil {          										 //agar xato bo'lsa
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})	 //xatoni qaytarish
		return                                                       //dasturdan chiqish
	}

	db := connectDB() 												 //bazaga ulanish
	//users jadvalini yaratish	 =================================>
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT, email TEXT, password TEXT, name TEXT, surname TEXT, age INT,  phone TEXT, promocode TEXT, status TEXT, roles TEXT, city TEXT, created_at TIMESTAMP, token TEXT, blocked BOOLEAN, warehouse_id INT)")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	user.Promocode = ""         //promokodni bo'sh qilish
	user.Status = "active"      //statusni faol qilish
	user.Roles = "user"         //roli foydalanuvchi qilish
	user.CreatedAt = time.Now() //yaratilgan vaqtni yozish
	user.Token = " "            //tokenni bo'sh qilish
	user.Blocked = false        //bloklanganligini false qilish

	if user.Username == "" { //agar username bo'sh bo'lsa
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is empty"}) //xatoni qaytarish
		return
	}
	if user.Email == "" { //agar email bo'sh bo'lsa
		c.JSON(http.StatusBadRequest, gin.H{"error": "email is empty"}) //xatoni qaytarish
		return
	}
	if user.Password == "" { //agar parol bo'sh bo'lsa
		c.JSON(http.StatusBadRequest, gin.H{"error": "password is empty"}) //xatoni qaytarish
		return
	}
	if user.Name == "" { //agar ism bo'sh bo'lsa
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is empty"}) //xatoni qaytarish
		return
	}
	if user.Surname == "" { //agar familiya bo'sh bo'lsa
		c.JSON(http.StatusBadRequest, gin.H{"error": "surname is empty"}) //xatoni qaytarish
		return
	}
	if user.Phone == "" { //agar telefon raqami bo'sh bo'lsa
		c.JSON(http.StatusBadRequest, gin.H{"error": "phone is empty"}) //xatoni qaytarish
		return
	}

	if user.Age == 0 { //agar yosh bo'sh bo'lsa
		c.JSON(http.StatusBadRequest, gin.H{"error": "age is empty"}) //xatoni qaytarish
		return
	}

	if user.Age < 16 { //agar yosh 16 dan kichik bo'lsa
		c.JSON(http.StatusBadRequest, gin.H{"error": "age is less than 16"}) //xatoni qaytarish
		return
	}

	if user.City == "" { //agar shahar bo'sh bo'lsa
		c.JSON(http.StatusBadRequest, gin.H{"error": "city is empty"}) //xatoni qaytarish
		return
	}

	//db in warehouse table in get all id if WarehouseID == warehouse table in list id element in id == WarehouseID create user

	idList := []int{}                                  //id lar uchun list
	rows, err := db.Query("SELECT id FROM warehouses") //id larini olish
	if err != nil {                                    //agar xato bo'lsa
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}) //xatoni qaytarish
		return
	}
	for rows.Next() { //id larni listga qo'shish
		var id int           //id uchun o'zgaruvchi
		err = rows.Scan(&id) //id ni olish
		if err != nil {      //agar xato bo'lsa
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}) //xatoni qaytarish
			return
		}
		idList = append(idList, id) //id larni listga qo'shish
	}

	for _, id := range idList { //id larni tekshirish
		if user.WarehouseID != id { //agar id lar teng bo'lmasa
			c.JSON(http.StatusBadRequest, gin.H{"error": "warehouse id is not exist"}) //xatoni qaytarish
			return
		} else {
			fmt.Println("ok")
			break
		}
	}

	var username string                                                                                //username uchun o'zgaruvchi
	err = db.QueryRow("SELECT username FROM users WHERE username = $1", user.Username).Scan(&username) //username ni bazadan olish
	if err == nil {                                                                                    //agar xato bo'lsa
		c.JSON(http.StatusBadRequest, gin.H{"error": "username already exist"}) //xatoni qaytarish
		return
	}

	_, err = db.Exec("INSERT INTO users (username, email, password, name, surname, age, phone, promocode, status, roles, city, created_at, token, blocked, warehouse_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)", user.Username, user.Email, passwordHash(user.Password), user.Name, user.Surname, user.Age, user.Phone, user.Promocode, user.Status, user.Roles, user.City, user.CreatedAt, user.Token, user.Blocked, user.WarehouseID) //bazaga yozish
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func login(c *gin.Context) {
	var user User
	err := c.BindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	db := connectDB()
	var username string
	var password string
	var token string
	var roles string
	err = db.QueryRow("SELECT username, password, token, roles FROM users WHERE username = $1", user.Username).Scan(&username, &password, &token, &roles)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "username or password is incorrect"})
		return
	}

	if !checkPasswordHash(user.Password, password) {
		fmt.Println(err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "username or password is incorrect"})
		return
	}

	if token == " " || token != " " {
		token, err = generateToken(username, password, roles)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		_, err = db.Exec("UPDATE users SET token = $1 WHERE username = $2", token, username)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func logout(c *gin.Context) {
	token := c.GetHeader("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")
	claims := jwt.MapClaims{}
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !tkn.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	db := connectDB()
	_, err = db.Exec("UPDATE users SET token = $1 WHERE username = $2", "", claims["username"])
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func addWarehouse(c *gin.Context) {
	//if such a name exists error else add warehouse to db name, address, phone, city, status, created_at, created_by = username
	token := c.GetHeader("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")
	claims := jwt.MapClaims{}
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})

	if claims["roles"] != "boss" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "you are not boss"})
		return
	}

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !tkn.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var warehouse Warehouse
	err = c.BindJSON(&warehouse)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if warehouse.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is empty"})
		return
	}

	if warehouse.City == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "city is empty"})
		return
	}

	warehouse.CreatedAt = time.Now()
	warehouse.CreatedBy = claims["username"].(string)
	warehouse.Status = "active"
	warehouse.Blocked = false

	db := connectDB()
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS warehouses (id SERIAL PRIMARY KEY, name TEXT, city TEXT, created_at TIMESTAMP, created_by TEXT, status TEXT, blocked BOOLEAN)")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var name string
	err = db.QueryRow("SELECT name FROM warehouses WHERE name = $1", warehouse.Name).Scan(&name)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name already exist"})
		return
	}

	_, err = db.Exec("INSERT INTO warehouses (name, city, created_at, created_by, status, blocked) VALUES ($1, $2, $3, $4, $5, $6)", warehouse.Name, warehouse.City, warehouse.CreatedAt, warehouse.CreatedBy, warehouse.Status, warehouse.Blocked)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func addCategory(c *gin.Context) {
	token := c.GetHeader("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")
	claims := jwt.MapClaims{}
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})

	if claims["roles"] != "boss" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "you are not creator or boss"})
		return
	}

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !tkn.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var category Category
	err = c.BindJSON(&category)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if category.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is empty"})
		return
	}
	category.CatID = generateUserId()
	category.CreatedAt = time.Now()
	category.CreatedBy = claims["username"].(string)
	category.Status = "active"

	db := connectDB()
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS categories (id SERIAL PRIMARY KEY, cat_id TEXT, name TEXT, description TEXT, created_at TIMESTAMP, created_by TEXT, status TEXT, warehouse_id INT)")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var name string
	var warehouse_id int
	//if db in name if any and warehouse_id and row in warehouse_id available return error
	err = db.QueryRow("SELECT name, warehouse_id FROM categories WHERE name = $1 AND warehouse_id = $2", category.Name, category.WarehouseID).Scan(&name, &warehouse_id)
	if err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name already exist"})
		return
	}

	_, err = db.Exec("INSERT INTO categories (cat_id, name, description, created_at, created_by, status, warehouse_id) VALUES ($1, $2, $3, $4, $5, $6, $7)", category.CatID, category.Name, category.Description, category.CreatedAt, category.CreatedBy, category.Status, category.WarehouseID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}
