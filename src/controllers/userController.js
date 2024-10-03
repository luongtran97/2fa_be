// Author: TrungQuanDev | https://youtube.com/@trungquandev
import { StatusCodes } from "http-status-codes";
import { pickUser } from "~/utils/formatters";
import { authenticator } from "otplib";
import qrcode from 'qrcode'
// LƯU Ý: Trong ví dụ về xác thực 2 lớp Two-Factor Authentication (2FA) này thì chúng ta sẽ sử dụng nedb-promises để lưu và truy cập dữ liệu từ một file JSON. Coi như file JSON này là Database của dự án.
const Datastore = require("nedb-promises");
const UserDB = Datastore.create("src/database/users.json");
const TwoFactorSecretKeyDB = Datastore.create(
  "src/database/2faSecretKeys.json"
);
const UserSessionDB = Datastore.create("src/database/user_sessions.json")
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

    // check nếu lần đầu khởi tạo 2 fa mà dưới db chưa có
    if (!twoFactorSecretKey) {
      // chưa có thì tạo mới
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

const setup2FA = async(req, res) => {
  try {
    // B1 lấy user từ bằng users
    const user = await UserDB.findOne({ _id: req.params.id });
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: "User not found!" });
      return;
    }

      // B2 Lấy 2fa secret key 2fa từ db
    const twoFactorSecretKey = await TwoFactorSecretKeyDB.findOne({
        user_id: user._id,
      });

      if(!twoFactorSecretKey){
        res.status(StatusCodes.NOT_FOUND).json({ message: "Two-Factor Secret  not found!" });
      }

      // B3 nếu user đã có secret key > kiểm tra OTP token từ client gửi lên 
      const clientOtpToken = req.body.otpToken
      const isValid = authenticator.verify({ token:clientOtpToken, secret: twoFactorSecretKey.value})


      if (!isValid) {
        res.status(StatusCodes.NOT_FOUND).json({ message: "Invalid OTP Token!" });
        return;
      }

      // B4 Nếu OTP token hợp lệ nghĩa là xác thực 2FA thành công, tiếp theo sẽ cập nhập lại thông tin require_2fa của user trong db
      const updatedUser = await UserDB.update(
        {_id:user._id },{$set:{require_2fa:true}}, {returnUpdatedDocs:true}
      )

      // sau mỗi hành động update, cần phải chạy compactDatafileAsync để nó loại bỏ object cũ và tạo 1 object mới 
      UserDB.compactDatafileAsync()

      // B5 Tùy vào dự án mà sẽ giữ phiên đăng nhập hợp lệ cho user, hoặc yêu cầu bắt buộc user phải đăng nhập lại, Cái này tùy theo nhu cầu
      // Ở đây sẽ chọn giữ phiên đăng nhập hợp lệ cho user giống như google, khi nào user chủ động đăng xuất và đăng nhập lại hoặc user đăng nhập trên device khác thì yêu cầu require_2fa
      // Vì user lúc này mới bật 2fa nên chúng ta sẽ tạo ra một phiên đăng nhập hợp lệ cho user với định danh trình duyệt hiện tại 
      const newUserSession = await UserSessionDB.insert({
        user_id : user._id,
        // lấy userAgent từ req.headers để định danh trình duyệt của user (device_id)
        device_id:req.header['user-agent'],
        // xác định phiên đăng nhập này là hợp lệ với 2FA
        is_2fa_verified:true,
        last_login: new Date().valueOf()
      })

      // B6 trả về dữ liệu cho FE
      res.status(StatusCodes.OK).json({
        ...pickUser(updatedUser),
        is_2fa_verified: newUserSession.is_2fa_verified,
        last_login: newUserSession.last_login,       
      })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error);
  }

}

export const userController = {
  login,
  getUser,
  logout,
  get2FaQrCode,
  setup2FA
};
