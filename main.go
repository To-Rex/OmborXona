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

type Magazine struct { //magazine
	ID          int       `json:"id"`           //id											1
	MagazineID  string    `json:"magazine_id"`  //magazine id									2
	WarehouseID int       `json:"warehouse_id"` //qaysi omborda									3
	Name        string    `json:"name"`         //nomi											4
	Description string    `json:"description"`  //eslatma										5
	CreatedAt   time.Time `json:"created_at"`   //yaratilgan vaqti								6
	CreatedBy   string    `json:"created_by"`   //yaratgan foydalanuvchi						7
	Status      string    `json:"status"`       //holati										8
}

type Product struct { //mahsulot
	ID          int       `json:"id"`           //id 											1
	CatID       string    `json:"cat_id"`       //kategoriyasi									2
	ProductID   string    `json:"product_id"`   //mahsulot id									3
	WarehouseID int   `json:"warehouse_id"` //qaysi omborda									4
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
type ProductHistory struct { //mahsulot tarixi
	ID          int       `json:"id"`           //id 											1
	CatID       string    `json:"cat_id"`       //kategoriyasi									2
	ProductID   int    `json:"product_id"`   //mahsulot id									3
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
	WarehouseID int       `json:"warehouse_id"` //qaysi omborda									4
	Name        string    `json:"name"`         //nomi											5
	Description string    `json:"description"`  //eslatma										6
	Picture     string    `json:"picture"`      //rasmi											7
	Cauntry     string    `json:"cauntry"`      //mamlakati										8
	Code        float64   `json:"code"`         //kodi											9
	Price       float64   `json:"price"`        //sotish narxi									10
	Addition    float64   `json:"addition"`     //qo'shimcha to'lov								11
	ReportStatus string   `json:"report_status"`//hisobot holati								12
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
	r.POST("/addProduct", addProduct)     //Mahsulot qo'shish
	r.POST("/addMagazine", addMagazine)   //Jadval qo'shish
	r.POST("/addMagazineProduct", addMagazineProduct) //Jadvalga mahsulot qo'shish
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

	if claims["roles"] != "boss"{
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

func addProduct(c *gin.Context) {
	token := c.GetHeader("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")
	claims := jwt.MapClaims{}
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})

	if claims["roles"] == "user" {
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
	var user User
	db := connectDB()
	err = db.QueryRow("SELECT id, username, email, password, name, surname, age, phone, status, roles, city, created_at, token, blocked, warehouse_id FROM users WHERE username = $1", claims["username"]).Scan(&user.ID, &user.Username, &user.Email, &user.Password, &user.Name, &user.Surname, &user.Age, &user.Phone, &user.Status, &user.Roles, &user.City, &user.CreatedAt, &user.Token, &user.Blocked, &user.WarehouseID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var product Product
	err = c.BindJSON(&product)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if product.Name == "" {   //agar name bo'sh bo'lsa
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is empty"}) //error qaytarish
		return
	}

	if product.Cauntry == "" {   //agar mamlakat bo'sh bo'lsa
		product.Cauntry = "Uzbekistan" //mamlakatni Uzbekiston qilish
	}

	if product.Code == 0 {   //agar kodi bo'sh bo'lsa
		product.Code = 1 //kodi 1 qilish
	}

	if product.Price < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "price is empty"})
		return
	}

	if product.Benicifits < 0 {
		product.Price -= product.Benicifits
	}

	if product.Discount <= 0 {
		product.Discount = 0
	}

	if product.Currency == "" {
		product.Currency = "UZS"
	}

	if product.Quantity < 0 || product.Quantity == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "quantity is empty"})
		return
	}

	if product.Guarantee < 0 || product.Guarantee == 0{
		product.Guarantee = 0
	}

	if product.Measurement == "" {
		product.Measurement = "DONA"
	}

	if product.Parts == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "parts is empty"})
		return
	}

	if product.Barcode == "" {
		product.Barcode = product.Name
	}

	if product.Brand == "" {
		product.Brand = "No brand"
	}
	
	if product.Type == "" {
		product.Type = "No type"
	}

	if product.Status == "" {
		product.Status = "active"
	}

	product.CreatedAt = time.Now()
	product.CreatedBy = claims["username"].(string)
	product.ProductID = generateUserId()
	if user.Roles != "boss" {
		product.WarehouseID = user.WarehouseID
	}else {
		product.WarehouseID = 1
	}
	if product.CatID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cat_id is empty"})
		return
	}
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, cat_id TEXT, product_id TEXT, warehouse_id FLOAT, name TEXT, description TEXT, picture TEXT, cauntry TEXT, code FLOAT, price FLOAT, benicifits FLOAT, discount FLOAT, currency TEXT, quantity FLOAT, guarantee FLOAT, measurement TEXT, parts TEXT, barcode TEXT, brand TEXT, type TEXT, created_at TIMESTAMP, created_by TEXT, status TEXT)")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_, err = db.Exec("INSERT INTO products (cat_id, product_id, warehouse_id, name, description, picture, cauntry, code, price, benicifits, discount, currency, quantity, guarantee, measurement, parts, barcode, brand, type, created_at, created_by, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)", product.CatID, product.ProductID, product.WarehouseID, product.Name, product.Description, product.Picture, product.Cauntry, product.Code, product.Price, product.Benicifits, product.Discount, product.Currency, product.Quantity, product.Guarantee, product.Measurement, product.Parts, product.Barcode, product.Brand, product.Type, product.CreatedAt, product.CreatedBy, product.Status)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var Report Report
	Report.ReportID = generateUserId()
	Report.ProductID = product.ProductID
	Report.WarehouseID = product.WarehouseID
	Report.Name = product.Name
	Report.Description = product.Description
	Report.Picture = product.Picture
	Report.Cauntry = product.Cauntry
	Report.Code = product.Code
	Report.Price = product.Price
	Report.Addition = 0
	Report.ReportStatus = "added"
	Report.Benicifits = 0
	Report.Discount = 0
	Report.Currency = product.Currency
	Report.Quantity = product.Quantity
	Report.Guarantee = product.Guarantee
	Report.Measurement = product.Measurement
	Report.Parts = product.Parts
	Report.Barcode = product.Barcode
	Report.Brand = product.Brand
	Report.Type = product.Type
	Report.CreatedAt = time.Now()
	Report.CreatedBy = product.CreatedBy
	Report.Status = product.Status

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS reports (id SERIAL PRIMARY KEY, report_id TEXT, product_id TEXT, warehouse_id FLOAT, name TEXT, description TEXT, picture TEXT, cauntry TEXT, code FLOAT, price FLOAT, addition FLOAT, report_status TEXT, benicifits FLOAT, discount FLOAT, currency TEXT, quantity FLOAT, guarantee FLOAT, measurement TEXT, parts TEXT, barcode TEXT, brand TEXT, type TEXT, created_at TIMESTAMP, created_by TEXT, status TEXT)")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	_, err = db.Exec("INSERT INTO reports (report_id, product_id, warehouse_id, name, description, picture, cauntry, code, price, addition, report_status, benicifits, discount, currency, quantity, guarantee, measurement, parts, barcode, brand, type, created_at, created_by, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)", Report.ReportID, Report.ProductID, Report.WarehouseID, Report.Name, Report.Description, Report.Picture, Report.Cauntry, Report.Code, Report.Price, Report.Addition, Report.ReportStatus, Report.Benicifits, Report.Discount, Report.Currency, Report.Quantity, Report.Guarantee, Report.Measurement, Report.Parts, Report.Barcode, Report.Brand, Report.Type, Report.CreatedAt, Report.CreatedBy, Report.Status)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func addMagazine(c *gin.Context){
	token := c.GetHeader("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")
	claims := jwt.MapClaims{}
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})

	if claims["roles"] != "boss"{
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

	var magazine Magazine
	if err := c.ShouldBindJSON(&magazine); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db := connectDB()
	magazine.CreatedAt = time.Now()
	magazine.CreatedBy = claims["username"].(string)
	magazine.MagazineID = generateUserId()
	magazine.Status = "active"

	if magazine.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is empty"})
		return
	}
	if magazine.Description == "" {
		magazine.Description = "no description"
	}
	if magazine.CreatedBy == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "created_by is empty"})
		return
	}
	if magazine.Status == "no active"{
		c.JSON(http.StatusBadRequest, gin.H{"error": "status is empty"})
		return
	}

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS magazines (id SERIAL PRIMARY KEY, magazine_id TEXT, warehouse_id FLOAT, name TEXT, description TEXT, created_at TIMESTAMP, created_by TEXT, status TEXT)")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err = db.Exec("INSERT INTO magazines (magazine_id, warehouse_id, name, description, created_at, created_by, status) VALUES ($1, $2, $3, $4, $5, $6, $7)", magazine.MagazineID, magazine.WarehouseID, magazine.Name, magazine.Description, magazine.CreatedAt, magazine.CreatedBy, magazine.Status)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func addMagazineProduct(c *gin.Context){
	token := c.GetHeader("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")
	claims := jwt.MapClaims{}
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})

	if claims["roles"] == "user" {
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

	//add magazineproduct update Catagory product update product
	
}