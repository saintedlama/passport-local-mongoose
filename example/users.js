import mongoose from 'mongoose'
import passportLocalMongoose from '../dist/index.js'

const UserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      unique: true,
    }
  }
)

UserSchema.plugin(passportLocalMongoose.default)

const UserModel = mongoose.model('users', UserSchema)

export {
  UserSchema,
  UserModel
}