import * as OAuth from "oauth";
import {TWITTER_CONFIG_1} from "../config";

interface TwitterFriendship {
  relationship: TwitterRelationship
}

interface TwitterRelationship {
  source: TwitterAccountInfo
  target: TwitterAccountInfo
}

interface TwitterAccountInfo {
  id: number,
  screen_name: string,
  following: boolean,
  followed_by: boolean,
  blocking?: boolean | null,
  blocked_by?: boolean | null
}

interface TwitterTweet {
  data: TwitterTweetData
}

interface TwitterTweetData {
  id: string,
  referenced_tweets?: TwitterReferenced[]
}

interface TwitterReferenced {
  type: string,
  id: string
}

const oauth = new OAuth.OAuth(
    "https://api.twitter.com/oauth/request_token",
    "https://api.twitter.com/oauth/access_token",
    TWITTER_CONFIG_1.twitterApiKey,
    TWITTER_CONFIG_1.twitterApiSecret,
    "1.0A",
    null,
    "HMAC-SHA1"
);

export const verifyFollowingStatus = async function(
    source: string,
    target: string) {
  const friendshipUrl = "https://api.twitter.com/1.1/friendships/show.json?source_screen_name=" +
      source + "&target_screen_name=" + target;
  const friendships = await twitterApiCall(friendshipUrl) as TwitterFriendship;
  if (friendships && friendships.relationship.source.following) {
    return true;
  }

  return false;
};

export const verifyRetweetStatus = async function(
    referencedTweetId: string,
    tweetId: string
) {
  const tweetUrl = "https://api.twitter.com/2/tweets/" + tweetId + "?expansions=referenced_tweets.id";
  const tweet = await twitterApiCall(tweetUrl) as TwitterTweet;

  if (tweet && tweet.data && tweet.data.referenced_tweets &&
      tweet.data.referenced_tweets.length > 0) {
    const referenced = tweet.data.referenced_tweets
        .filter((reference) => reference.id === referencedTweetId);
    return referenced && referenced.length > 0;
  }

  return false;
};

const twitterApiCall =
  async function(url: string) : Promise<TwitterFriendship | TwitterTweet> {
    return new Promise((resolve, reject) => {
      oauth.get(
          url,
          TWITTER_CONFIG_1.twitterAccessKey,
          TWITTER_CONFIG_1.twitterAccessSecret,
          (err: { statusCode: number; data?: any },
              body?: string | Buffer) => {
            if (err) {
              reject(err);
              return;
            }

            if (!body) {
              return;
            }

            resolve(JSON.parse(body as string));
          });
    });
  };
