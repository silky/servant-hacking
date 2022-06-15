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
                                        Context((:.), EmptyContext), Server, serveWithContext)
import Network.Wai.Handler.Warp         (run)
import Servant.HTML.Blaze               (HTML)
import Servant.Server.Experimental.Auth (AuthServerData, AuthHandler , mkAuthHandler)
import Text.Hamlet                      (Html, shamlet)
import Web.Cookie                       (parseCookies)

newtype Account = Account { unAccount :: Text }

database :: Map ByteString Account
database = Map.fromList [ ("key1", Account "Noon van der Silk") ]

lookupAccount :: ByteString -> Handler Account
lookupAccount key
  = case Map.lookup key database of
      Nothing   -> throwError (err403 { errBody = "Invalid Cookie" })
      Just user -> return user

authHandler :: AuthHandler Request Account
authHandler = mkAuthHandler handler
  where
    maybeToEither e = maybe (Left e) Right
    throw401 msg = throwError $ err401 { errBody = msg }
    handler req = either throw401 lookupAccount $ do
      cookie <- maybeToEither "Missing cookie header" $ lookup "cookie" $ requestHeaders req
      maybeToEither "Missing token in cookie" $ lookup "servant-auth-cookie" $ parseCookies cookie

type AuthGenApi
  =    "private" :> AuthProtect "cookie-auth" :> Get '[HTML] Html
  :<|> "public"  :> Get '[HTML] Html

genAuthApi :: Proxy AuthGenApi
genAuthApi = Proxy

type instance AuthServerData (AuthProtect "cookie-auth") = Account

genAuthServerContext :: Context '[AuthHandler Request Account]
genAuthServerContext = authHandler :. EmptyContext

genAuthServer :: Server AuthGenApi
genAuthServer =
  let privateDataFunc (Account name) = return $ [shamlet|this is secret: #{name}|]
      publicData = return [shamlet|public data.|]
   in privateDataFunc :<|> publicData

main :: IO ()
main = do
  run 8081 (serveWithContext genAuthApi genAuthServerContext genAuthServer)
