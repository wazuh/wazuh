// The Statistics strategy uses the measure of each end-start time for each
// query executed against the db to calculate the mean, variance and standard deviation
// and pick the server which the lowest mean and deviation
var StatisticsStrategy = exports.StatisticsStrategy = function(replicaset) {
  this.replicaset = replicaset;
  // Logger api
  this.Logger = null;  
}

// Starts any needed code
StatisticsStrategy.prototype.start = function(callback) {
  callback && callback(null, null);
}

StatisticsStrategy.prototype.stop = function(callback) {
  callback && callback(null, null);
}

StatisticsStrategy.prototype.checkoutConnection = function(tags, secondaryCandidates) {
  // Servers are picked based on the lowest ping time and then servers that lower than that + secondaryAcceptableLatencyMS
  // Create a list of candidat servers, containing the primary if available
  var candidateServers = [];

  // If we have not provided a list of candidate servers use the default setup
  if(!Array.isArray(secondaryCandidates)) {
    candidateServers = this.replicaset._state.master != null ? [this.replicaset._state.master] : [];
    // Add all the secondaries
    var keys = Object.keys(this.replicaset._state.secondaries);
    for(var i = 0; i < keys.length; i++) {
      candidateServers.push(this.replicaset._state.secondaries[keys[i]])
    }
  } else {
    candidateServers = secondaryCandidates;
  }

  // Final list of eligable server
  var finalCandidates = [];

  // If we have tags filter by tags
  if(tags != null && typeof tags == 'object') {
    // If we have an array or single tag selection
    var tagObjects = Array.isArray(tags) ? tags : [tags];
    // Iterate over all tags until we find a candidate server
    for(var _i = 0; _i < tagObjects.length; _i++) {
      // Grab a tag object
      var tagObject = tagObjects[_i];
      // Matching keys
      var matchingKeys = Object.keys(tagObject);
      // Remove any that are not tagged correctly
      for(var i = 0; i < candidateServers.length; i++) {
        var server = candidateServers[i];
        // If we have tags match
        if(server.tags != null) {
          var matching = true;

          // Ensure we have all the values
          for(var j = 0; j < matchingKeys.length; j++) {
            if(server.tags[matchingKeys[j]] != tagObject[matchingKeys[j]]) {
              matching = false;
              break;
            }
          }

          // If we have a match add it to the list of matching servers
          if(matching) {
            finalCandidates.push(server);
          }
        }
      }
    }
  } else {
    // Final array candidates
    var finalCandidates = candidateServers;
  }

  // If no candidates available return an error
  if(finalCandidates.length == 0) return new Error("No replica set members available for query");
  // Pick a random server
  return finalCandidates[Math.round(Math.random(1000000) * (finalCandidates.length - 1))].checkoutReader();
}
