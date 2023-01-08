import {parse} from "node-html-parser";

const RETWEET_ATTRIBUTE = "timeline-Tweet--isRetweet";
const RENDERED_TWEET_ID = "data-rendered-tweet-id";

export const parseHtmlString = (htmlString: string, tweetId: string) => {
  const parsedHtml = parse(htmlString);

  const retweets = parsedHtml.getElementsByTagName("div")
      .filter((div) => div.attributes.class.includes(RETWEET_ATTRIBUTE))
      .filter((retweet) => retweet.hasAttribute(RENDERED_TWEET_ID) &&
          retweet.getAttribute(RENDERED_TWEET_ID) === tweetId);

  return retweets && retweets.length > 0;
};
