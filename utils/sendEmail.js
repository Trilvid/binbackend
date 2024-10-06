const nodemailer = require('nodemailer')
const hbs = require('nodemailer-express-handlebars')
module.exports = async (email,subject,text)=>{
    try {
        const transporter = nodemailer.createTransport({
            host: process.env.HOST,
            service: process.env.SERVICE,
            port: Number(process.env.EMAIL_PORT),
            secure:Boolean(process.env.SECURE),
            auth:{
                user:process.env.USER,
                pass:process.env.PASS
            }
        })

        await transporter.sendMail({
            from:process.env.USER,
            to:email,
            subject:subject,
            text:text,
            // template:'index'
        });

        // transporter.use('compile',hbs({
        //     viewEngine:'express-handlebars',
        //     viewPath:'./view/'
        // }))

        
        console.log('email sent successfully')
    } catch (error) {
        console.log(`error ${error}... email not sent`)
    }
}



// const nodemailer = require('nodemailer');
// const pug = require('pug');
// const htmlToText = require('html-to-text');
// const path = require('path');

// module.exports = class Email {
//   constructor(user, url) {
//     this.to = user.email;
//     this.firstName = user.firstname;
//     this.url = url;
//     this.from = `Joyce Williston <${process.env.USER}>`;
//   }

//   newTransport() {
//     if (process.env.NODE_ENV === 'production') {
//       // Sendgrid
//       return nodemailer.createTransport({
//         service: process.env.SERVICE,
//             port: Number(process.env.EMAIL_PORT),
//             // secure:Boolean(process.env.SECURE),
//             auth:{
//                 user:process.env.USER,
//                 pass:process.env.PASS
//             }
//       });
//     }

//     return nodemailer.createTransport({
//       host: process.env.HOST,
//       service: process.env.SERVICE,
//       port: Number(process.env.EMAIL_PORT),
//     //   secure:Boolean(process.env.SECURE),
//       auth:{
//           user:process.env.USER,
//           pass:process.env.PASS
//       }
//     });
//   }

//   // Send the actual email
//   async send(template, subject) {
//     // 1) Render HTML based on a pug template
//     // const html = pug.renderFile(`${__dirname}/../view/email/${template}.pug`, {
//     //   firstName: this.firstName,
//     //   url: this.url,
//     //   subject
//     // });

//     const filePath = path.join(__dirname, '..', 'view', 'email', `${template}.pug`);
//     const html = pug.renderFile(filePath, {
//     firstName: this.firstName,
//     url: this.url,
//     subject
//     });


//     // 2) Define email options
//     const mailOptions = {
//       from: this.from,
//       to: this.to,
//       subject,
//       html,
//     //   text: htmlToText.fromString(html)
//     };

//     // 3) Create a transport and send email
//     await this.newTransport().sendMail(mailOptions);
//   }

//   async sendWelcome() {
//     await this.send('welcome', 'Welcome to the OceanVolte Community!');
//   }

//   async sendPasswordReset() {
//     await this.send(
//       'passwordReset',
//       'Your password reset token (valid for only 10 minutes)'
//     );
//   }
// };
