{-# language TypeFamilies    #-}
{-# language QuasiQuotes     #-}
{-# language TemplateHaskell #-}

module Main where

import Data.ByteString                  (ByteString)
import Data.Map                         (Map)
import Data.Map qualified               as Map
import Data.Text                        (Text)
import Network.Wai                      (Request, requestHeaders)
import Servant                          (Handler, err401, err403, throwError, errBody,
                                        type (:>), (:<|>)(..), Get, AuthProtect, Proxy(Proxy),
                                        Context((:.), EmptyContext), Server, serveWithContext,
                                        Header, Headers(Headers), addHeader)
import Network.Wai.Handler.Warp         (run)
import Servant.HTML.Blaze               (HTML)
import Servant.Server.Experimental.Auth (AuthServerData, AuthHandler , mkAuthHandler)
import Text.Hamlet                      (Html, shamlet)
import Web.Cookie                       (parseCookies, SetCookie(..), sameSiteStrict, defaultSetCookie)

newtype Account = Account { unAccount :: Text }

database :: Map ByteString Account
database = Map.fromList [ ("key1", Account "Noon van der Silk") ]

lookupAccount :: ByteString -> Handler Account
lookupAccount key
  = case Map.lookup key database of
      Nothing   -> throwError (err403 { errBody = "Invalid Cookie" })
      Just user -> return user

-- type AuthContext r = AuthHandler Request (SessionFor r)
-- authHandler :: AuthContext 'Anyone
-- authHandler :: AuthHandler Request SessionFor
--
type AuthContext = AuthHandler Request SessionFor

authHandler :: AuthContext
authHandler = mkAuthHandler handler
  where
    maybeToEither e = maybe (Left e) Right
    throw401 msg = throwError $ err401 { errBody = msg }
    handler :: Request -> Handler SessionFor
    handler req = do
      let h = requestHeaders req
          c = lookup "cookie" h
      case c of
        Nothing -> throw401 "Missing 'Cookie' header."
        Just c' -> do
          let p = parseCookies c'
              ac = lookup "servant-auth-cookie" p
          case ac of
            Nothing  -> throw401 "Missing 'servant-auth-cookie' in cookie."
            Just ac' -> do
              acc <- lookupAccount ac'
              pure $ (addHeader mkSessionCookie acc)

mkSessionCookie :: SetCookie
mkSessionCookie =
  defaultSetCookie
    { setCookieName     = "b3-secret-cookie"
    , setCookieValue    = "cookie-data"
    , setCookieMaxAge   = Just oneWeek
    , setCookiePath     = Just "/"
    , setCookieSameSite = Just sameSiteStrict
    , setCookieHttpOnly = True
    , setCookieSecure   = False
    }
    where
      oneWeek = 3600 * 24 * 7

type SessionFor = Headers '[Header "Set-Cookie" SetCookie] Account

type AuthGenApi
  =    "private" :> AuthProtect "cookie-auth" :> Get '[HTML] Html
  :<|> "public"  :> Get '[HTML] Html

genAuthApi :: Proxy AuthGenApi
genAuthApi = Proxy

type instance AuthServerData (AuthProtect "cookie-auth") = SessionFor

genAuthServerContext :: Context '[AuthContext]
genAuthServerContext = authHandler :. EmptyContext

genAuthServer :: Server AuthGenApi
genAuthServer =
  let privateDataFunc (Headers (Account name) _) = return $ [shamlet|this is secret: #{name}|]
      publicData = return [shamlet|public data.|]
   in privateDataFunc :<|> publicData

main :: IO ()
main = do
  run 8081 (serveWithContext genAuthApi genAuthServerContext genAuthServer)
