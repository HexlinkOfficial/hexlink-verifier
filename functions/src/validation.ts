import {getAuth} from "firebase-admin/auth";
import fetch from "node-fetch";
import * as OAuth from "oauth";
import {parseHtmlString} from "./util/parse";

interface Response {
  headers: Map<string, string | number>,
  body: string
}

export const verifiedByIdToken = async function(idToken: string) {
  return await getAuth().verifyIdToken(idToken);
};

export const verifyFollowingStatus = async function(
    accessToken: string,
    secret: string,
    source: string,
    target: string
) {
  console.log("Start to verify following status.");
  const oauth = new OAuth.OAuth(
      "https://api.twitter.com/oauth/request_token",
      "https://api.twitter.com/oauth/access_token",
      "VpF5dCeVSjJWvpXhWaX0GFwon",
      "tNcW9REoocaLvOzpLI2L8PxweDRbM9GMdbvEf9RsoLoy6VAQIz",
      "1.0A",
      null,
      "HMAC-SHA1"
  );

  const getFriendshipUrl = "https://api.twitter.com/1.1/friendships/show.json?source_screen_name=" +
      source + "&target_screen_name=" + target;

  oauth.get(getFriendshipUrl, accessToken, secret,
      function(err, data, response) {
        if (err) {
          console.log(err);
        } else {
          if (response) {
            return true;
          }
        }

        return false;
      });

  return false;
};

export const verifyRetweetStatus = async function(
    source: string,
    tweetId: string
) {
  console.log("Start to verify retweet status.");
  const getTimelineUrl = "https://cdn.syndication.twimg.com/timeline/profile?screen_name=" + source;
  const response = await fetch(getTimelineUrl);
  if (!response.ok) {
    return false;
  }

  const responseObj: Response = await response.json() as Response;
  if (!responseObj) {
    return false;
  }

  const body = responseObj.body;
  return parseHtmlString(body, tweetId);
};
