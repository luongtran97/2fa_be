// Author: TrungQuanDev | https://youtube.com/@trungquandev
import { StatusCodes } from "http-status-codes";
import { pickUser } from "~/utils/formatters";
import { authenticator } from "otplib";
import qrcode from 'qrcode'
// LƯU Ý: Trong ví dụ về xác thực 2 lớp Two-Factor Authentication (2FA) này thì chúng ta sẽ sử dụng nedb-promises để lưu và truy cập dữ liệu từ một file JSON. Coi như file JSON này là Database của dự án.
const Datastore = require("nedb-promises");
const UserDB = Datastore.create("src/database/users.json");
const TwoFactorSecretKeyDB = Datastore.create(
  "src/database/2fa_secret_keys.json"
);
const SERVICE_NAME = "2-FA luongtrandev"

const login = async (req, res) => {
  try {
    const user = await UserDB.findOne({ email: req.body.email });
    // Không tồn tại user
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: "User not found!" });
      return;
    }
    // Kiểm tra mật khẩu "đơn giản". LƯU Ý: Thực tế phải dùng bcryptjs để hash mật khẩu, đảm bảo mật khẩu được bảo mật. Ở đây chúng ta làm nhanh gọn theo kiểu so sánh string để tập trung vào nội dung chính là 2FA.
    // Muốn học về bcryptjs cũng như toàn diện kiến thức đầy đủ về việc làm một trang web Nâng Cao thì các bạn có thể theo dõi khóa MERN Stack Advanced này. (Public lên phần hội viên của kênh vào tháng 12/2024)
    // https://www.youtube.com/playlist?list=PLP6tw4Zpj-RJbPQfTZ0eCAXH_mHQiuf2G
    if (user.password !== req.body.password) {
      res
        .status(StatusCodes.NOT_ACCEPTABLE)
        .json({ message: "Wrong password!" });
      return;
    }

    res.status(StatusCodes.OK).json(pickUser(user));
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error);
  }
};

const getUser = async (req, res) => {

  try {
    const user = await UserDB.findOne({ _id: req.params.id });
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: "User not found!" });
      return;
    }

    res.status(StatusCodes.OK).json(pickUser(user));
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error);
  }
};

const logout = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id });
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: "User not found!" });
      return;
    }

    // Xóa phiên của user trong Database > user_sessions tại đây khi đăng xuất

    res.status(StatusCodes.OK).json({ loggedOut: true });
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error);
  }
};

const get2FaQrCode = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id });
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: "User not found!" });
      return;
    }

    // Biến lưu trữ 2fa secret key của user
    let twoFactorSecretKeyValue = null;
    
    // Lấy 2fa secret key 2fa từ db
    const twoFactorSecretKey = await TwoFactorSecretKeyDB.findOne({
      user_id: user._id,
    });
    console.log("🚀 ~ twoFactorSecretKey:", twoFactorSecretKey)

    // check nếu lần đầu khởi tạo 2 fa mà dưới db chưa có
    if (!twoFactorSecretKey) {
      // chưa có thì tạo mới
      console.log('1234')
      const newTwoFactorSecretKey = await TwoFactorSecretKeyDB.insert({
        user_id: user._id,
        value: authenticator.generateSecret(), // từ thư viện otplib tạo ra một random secret key mới đúng chuẩn
      });
      twoFactorSecretKeyValue = newTwoFactorSecretKey.value;
    } else {
      // nếu đã có thi lấy ra sử dụng
      twoFactorSecretKeyValue = twoFactorSecretKey.value;
    }

    // tạo OTP token 
    const otpAuthToken = authenticator.keyuri(
      user.username, SERVICE_NAME,twoFactorSecretKeyValue
    ) // hàm này nhận vào 3 tham số tên người dung, tên service, factor secterkeyvalue đã tạo ở trên

    // tạo 1 ảnh qr code từ otp token để gửi về cho client
    const QrCodeUrl = await qrcode.toDataURL(otpAuthToken)

    res.status(StatusCodes.OK).json({ qrcode: QrCodeUrl})

  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error);
  }
};

export const userController = {
  login,
  getUser,
  logout,
  get2FaQrCode,
};
